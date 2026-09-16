rule PEiD_00503_DZA_Patcher_v1_3____DZA_ {
  meta:
    description = "[DZA Patcher v1.3 -> DZA]"
    ep_only     = "true"

  strings:
    $a = { EB 08 35 48 34 30 4C 31 4E 00 60 E8 00 00 00 00 5D 8B D5 81 ED 44 73 40 00 2B 95 74 74 40 00 83 EA 10 89 95 70 74 40 00 8B 44 24 20 25 00 00 FF FF 80 38 4D 74 07 2D 00 00 01 00 EB F4 93 89 85 7C 74 40 00 8D BD 8C 74 40 00 E8 83 00 00 00 89 85 80 74 40 00 }

  condition:
    $a
}