rule TTP_XOR_QUAD_CurrentVersionRun_3ec7 {
  strings:
    $key_3ec7 = { 6d a8 [2] 49 a6 [2] 62 8a [2] 4c a8 [2] 58 b3 [2] 57 a9 [2] 49 b4 [2] 4b b5 [2] 50 b3 [2] 4c b4 [2] 50 9b }

  condition:
    any of them
}