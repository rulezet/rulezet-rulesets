rule PEiD_01190_MSLRH_0_32a__fake_ASPack_2_12_____emadicius_ {
  meta:
    description = "[MSLRH 0.32a (fake ASPack 2.12) -> emadicius]"
    ep_only     = "true"

  strings:
    $a = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 00 00 00 EB 5D BB ED FF FF FF 03 DD 81 EB 00 73 00 00 61 EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 6B }

  condition:
    $a
}