rule PEiD_01199_MSLRH_0_32a__fake_PC_Guard_4_xx_____emadicius_ {
  meta:
    description = "[MSLRH 0.32a (fake PC-Guard 4.xx) -> emadicius]"
    ep_only     = "false"

  strings:
    $a = { FC 55 50 E8 00 00 00 00 5D EB 01 E3 60 E8 03 00 00 00 D2 EB 0B 58 EB 01 48 40 EB 01 35 FF E0 E7 61 58 5D EB 05 E8 EB 04 40 00 EB FA E8 0A 00 00 00 E8 EB 0C 00 00 E8 F6 FF FF FF E8 F2 FF FF FF 83 C4 08 74 04 75 02 EB 02 EB 01 81 50 E8 02 00 00 00 29 5A 58 }

  condition:
    $a
}