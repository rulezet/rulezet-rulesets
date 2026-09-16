rule PEiD_01902_PureBasic_4_x_DLL____Neil_Hodgson_ {
  meta:
    description = "[PureBasic 4.x DLL -> Neil Hodgson]"
    ep_only     = "true"

  strings:
    $a = { 83 7C 24 08 01 75 0E 8B 44 24 04 A3 ?? ?? ?? 10 E8 22 00 00 00 83 7C 24 08 02 75 00 83 7C 24 08 00 75 05 E8 ?? 00 00 00 83 7C 24 08 03 75 00 B8 01 00 00 00 C2 0C 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? 0F 00 00 A3 }

  condition:
    $a
}