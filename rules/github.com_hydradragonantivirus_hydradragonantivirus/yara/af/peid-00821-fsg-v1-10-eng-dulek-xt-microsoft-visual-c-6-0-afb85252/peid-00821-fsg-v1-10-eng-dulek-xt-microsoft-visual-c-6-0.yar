rule PEiD_00821_FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___6_0__ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0)]"
    ep_only     = "true"

  strings:
    $a = { EB 02 AB 35 EB 02 B5 C6 8D 05 80 ?? ?? 00 C1 C2 11 BE F4 00 00 00 F7 DB F7 DB 0F BE 38 E8 }

  condition:
    $a
}