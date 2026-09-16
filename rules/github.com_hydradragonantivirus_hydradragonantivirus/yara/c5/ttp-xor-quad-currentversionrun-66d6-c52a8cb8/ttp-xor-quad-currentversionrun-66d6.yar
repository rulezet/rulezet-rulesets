rule TTP_XOR_QUAD_CurrentVersionRun_66d6 {
  strings:
    $key_66d6 = { 35 b9 [2] 11 b7 [2] 3a 9b [2] 14 b9 [2] 00 a2 [2] 0f b8 [2] 11 a5 [2] 13 a4 [2] 08 a2 [2] 14 a5 [2] 08 8a }

  condition:
    any of them
}