rule PEiD_01901_PureBasic_4_x____Neil_Hodgson_ {
  meta:
    description = "[PureBasic 4.x -> Neil Hodgson]"
    ep_only     = "true"

  strings:
    $a = { 68 ?? ?? 00 00 68 00 00 00 00 68 ?? ?? ?? 00 E8 ?? ?? ?? 00 83 C4 0C 68 00 00 00 00 E8 ?? ?? ?? 00 A3 ?? ?? ?? 00 68 00 00 00 00 68 00 10 00 00 68 00 00 00 00 E8 ?? ?? ?? 00 A3 }

  condition:
    $a
}