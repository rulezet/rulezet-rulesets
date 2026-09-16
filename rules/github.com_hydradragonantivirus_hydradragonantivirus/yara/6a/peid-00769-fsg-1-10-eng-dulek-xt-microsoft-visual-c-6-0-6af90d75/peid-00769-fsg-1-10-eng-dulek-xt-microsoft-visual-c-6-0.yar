rule PEiD_00769_FSG_1_10__Eng_____dulek_xt_____Microsoft_Visual_C___6_0__ {
  meta:
    description = "[FSG 1.10 (Eng) -> dulek/xt -> (Microsoft Visual C++ 6.0)]"
    ep_only     = "true"

  strings:
    $a = { 03 DE EB 01 F8 B8 80 ?? 42 00 EB 02 CD 20 68 17 A0 B3 AB EB 01 E8 59 0F B6 DB 68 0B A1 B3 AB EB 02 CD 20 5E 80 CB AA 2B F1 EB 02 CD 20 43 0F BE 38 13 D6 80 C3 47 2B FE EB 01 F4 03 FE EB 02 4F 4E 81 EF 93 53 7C 3C 80 C3 29 81 F7 8A 8F 67 8B 80 C3 C7 2B FE }

  condition:
    $a
}