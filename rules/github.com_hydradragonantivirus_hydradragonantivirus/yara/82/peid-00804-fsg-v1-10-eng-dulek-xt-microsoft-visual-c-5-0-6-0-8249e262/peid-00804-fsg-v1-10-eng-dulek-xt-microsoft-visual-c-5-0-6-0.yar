rule PEiD_00804_FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___5_0___6_0__ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 5.0 / 6.0)]"
    ep_only     = "true"

  strings:
    $a = { 33 D2 0F BE D2 EB 01 C7 EB 01 D8 8D 05 80 ?? ?? ?? EB 02 CD 20 EB 01 F8 BE F4 00 00 00 EB }

  condition:
    $a
}