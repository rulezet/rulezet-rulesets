import "pe"
rule PowerBASIC_CC_3_0x {
  strings:
    $a0 = { 55 8B EC 53 56 57 BB 00 ?? ?? 00 66 2E F7 05 ?? ?? ?? 00 04 00 0F 85 }

  condition:
    $a0 at pe.entry_point
}