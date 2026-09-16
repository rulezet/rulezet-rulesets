rule PEiD_00812_FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___6_0___7_0__ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0 / 7.0)]"
    ep_only     = "true"

  strings:
    $a = { F7 DB 80 EA BF B9 2F 40 67 BA EB 01 01 68 AF ?? A7 BA 80 EA 9D 58 C1 C2 09 2B C1 8B D7 68 }

  condition:
    $a
}