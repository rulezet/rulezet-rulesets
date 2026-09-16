rule TTP_XOR_QUAD_CurrentVersionRun_66eb {
  strings:
    $key_66eb = { 35 84 [2] 11 8a [2] 3a a6 [2] 14 84 [2] 00 9f [2] 0f 85 [2] 11 98 [2] 13 99 [2] 08 9f [2] 14 98 [2] 08 b7 }

  condition:
    any of them
}