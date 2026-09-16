import "pe"
rule TTP_VirtualAlloc_RWX_tight_1 {
  meta:
    author      = "@captainGeech42,@stvemillertime"
    description = "Look for PE files that make RWX calls to VirtualAlloc (xref'd against IAT entry)"
    date        = "2024-01-24"
    version     = "1"
    DaysofYARA  = "23/100"

  strings:
                            $c_32_1 = { 6a 40 68 00 ?? 00 00 [4-20] ff 15 }

  condition:
            uint16be(0) == 0x4d5a and (
      uint16(uint32(0x3c) + 0x18) == 0x10b and        $c_32_1 and
      for any imp in pe.import_details: (
        imp.library_name == "KERNEL32.dll" and
        for any func in imp.functions: (
          func.name == "VirtualAlloc" and
          uint32(@c_32_1 + !c_32_1) & 0xfffff == func.rva          )
      )
    )
}