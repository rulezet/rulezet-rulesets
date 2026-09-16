rule TTP_XOR_QUAD_CurrentVersionRun_69c7 {
  strings:
    $key_69c7 = { 3a a8 [2] 1e a6 [2] 35 8a [2] 1b a8 [2] 0f b3 [2] 00 a9 [2] 1e b4 [2] 1c b5 [2] 07 b3 [2] 1b b4 [2] 07 9b }

  condition:
    any of them
}