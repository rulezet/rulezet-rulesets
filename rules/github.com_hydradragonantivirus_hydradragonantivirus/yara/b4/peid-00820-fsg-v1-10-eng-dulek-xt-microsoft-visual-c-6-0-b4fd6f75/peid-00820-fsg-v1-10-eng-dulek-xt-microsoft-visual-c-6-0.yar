rule PEiD_00820_FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___6_0__ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0)]"
    ep_only     = "true"

  strings:
    $a = { EB 01 4D 83 F6 4C 68 80 ?? ?? 00 EB 02 CD 20 5B EB 01 23 68 48 1C 2B 3A E8 02 00 00 00 38 }

  condition:
    $a
}