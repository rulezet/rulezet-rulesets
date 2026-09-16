rule PEiD_00813_FSG_v1_10__Eng_____dulek_xt_____Microsoft_Visual_C___6_0___ASM__ {
  meta:
    description = "[FSG v1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0 / ASM)]"
    ep_only     = "true"

  strings:
    $a = { F7 D0 EB 02 CD 20 BE BB 74 1C FB EB 02 CD 20 BF 3B ?? ?? FB C1 C1 03 33 F7 EB 02 CD 20 68 }

  condition:
    $a
}