rule PEiD_01753_PowerBASIC_Win_7_0x_ {
  meta:
    description = "[PowerBASIC/Win 7.0x]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 53 56 57 BB 00 ?? 40 00 66 2E F7 05 ?? ?? 40 00 04 00 0F 85 DB 00 00 00 }

  condition:
    $a
}