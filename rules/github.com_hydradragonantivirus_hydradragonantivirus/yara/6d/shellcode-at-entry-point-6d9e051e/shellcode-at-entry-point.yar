import "pe"
rule shellcode_at_entry_point {
  meta:
    author      = "nex"
    description = "Matched shellcode byte patterns"
    modified    = "Glenn Edwards (@hiddenillusion)"

  condition:
    uint16be(pe.entry_point) == 0x648b and uint8(pe.entry_point + 2) == 0x64 or
    uint16be(pe.entry_point) == 0x64a1 and uint8(pe.entry_point + 2) == 0x30 or
    uint32be(pe.entry_point) == 0x648b1530 or
    uint32be(pe.entry_point) == 0x648b3530 or
    uint32be(pe.entry_point) == 0x558bec83 and uint8(pe.entry_point + 4) == 0xc4 or
    uint32be(pe.entry_point) == 0x558bec81 and uint8(pe.entry_point + 4) == 0xec or
    uint32be(pe.entry_point) == 0x558bece8 or
    uint32be(pe.entry_point) == 0x558bece9
}