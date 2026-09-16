rule PEiD_01751_PowerBASIC_CC_3_0x_ {
  meta:
    description = "[PowerBASIC/CC 3.0x]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 53 56 57 BB 00 ?? ?? 00 66 2E F7 05 ?? ?? ?? 00 04 00 0F 85 }

  condition:
    $a
}