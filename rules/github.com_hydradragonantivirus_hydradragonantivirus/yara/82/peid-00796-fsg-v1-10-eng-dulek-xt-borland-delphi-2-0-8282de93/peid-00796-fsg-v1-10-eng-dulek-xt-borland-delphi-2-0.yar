rule PEiD_00796_FSG_v1_10__Eng_____dulek_xt_____Borland_Delphi_2_0__ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Borland Delphi 2.0)]"
    ep_only     = "true"

  strings:
    $a = { EB 01 56 E8 02 00 00 00 B2 D9 59 68 80 ?? 41 00 E8 02 00 00 00 65 32 59 5E EB 02 CD 20 BB }

  condition:
    $a
}