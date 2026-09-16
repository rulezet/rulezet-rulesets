rule PEiD_03369_Vx__ARCV_4_ {
  meta:
    description = "[Vx: ARCV.4]"
    ep_only     = "true"

  strings:
    $a = { E8 00 00 5D 81 ED 06 01 81 FC 4F 50 74 0B 8D B6 86 01 BF 00 01 57 A4 EB 11 1E 06 }

  condition:
    $a
}