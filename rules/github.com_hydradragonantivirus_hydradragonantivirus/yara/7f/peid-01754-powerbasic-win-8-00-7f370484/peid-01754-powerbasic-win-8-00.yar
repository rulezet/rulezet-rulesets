rule PEiD_01754_PowerBASIC_Win_8_00_ {
  meta:
    description = "[PowerBASIC/Win 8.00]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 53 56 57 BB 00 ?? ?? 00 66 2E F7 05 ?? ?? 40 00 04 00 75 05 E9 14 04 00 00 E9 19 02 }

  condition:
    $a
}