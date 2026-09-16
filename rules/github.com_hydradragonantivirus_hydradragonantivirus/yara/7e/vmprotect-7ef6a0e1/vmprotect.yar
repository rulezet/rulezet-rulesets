import "pe"
rule VMProtect: VMProtect Software {
  meta:
    author = "_pusher_"
    date   = "2016-08"

  strings:
        $bb0 = "\x00\x00GetModuleHandleA\x00" ascii
        $bb1 = "\x00\x00GetModuleHandleW\x00" ascii
        $bb2 = "\x00\x00ExitProcess\x00" ascii

        $a1  = "\x00\x00LoadLibraryA\x00" ascii
        $cc0 = "\x00\x00GetModuleFileNameW\x00" ascii
        $cc1 = "\x00\x00GetModuleFileNameA\x00" ascii

  condition:
    (
      for any of ($bb*): ($ in (pe.sections[pe.section_index(pe.entry_point)].raw_data_offset..pe.sections[pe.section_index(pe.entry_point)].raw_data_offset + pe.sections[pe.section_index(pe.entry_point)].raw_data_size))
    ) and
    ($a1 in (pe.sections[pe.section_index(pe.entry_point)].raw_data_offset..pe.sections[pe.section_index(pe.entry_point)].raw_data_offset + pe.sections[pe.section_index(pe.entry_point)].raw_data_size))
    and
    (
      for any of ($cc*): ($ in (pe.sections[pe.section_index(pe.entry_point)].raw_data_offset..pe.sections[pe.section_index(pe.entry_point)].raw_data_offset + pe.sections[pe.section_index(pe.entry_point)].raw_data_size))
    )
    and
    (
      (pe.sections[pe.section_index(pe.entry_point)].characteristics == 0xE2000020) or
      (pe.sections[pe.section_index(pe.entry_point)].characteristics == 0xE0000060) or
      (pe.sections[pe.section_index(pe.entry_point)].characteristics == 0xE2000060) or
      (pe.sections[pe.section_index(pe.entry_point)].characteristics == 0x60000060)
    )
  }