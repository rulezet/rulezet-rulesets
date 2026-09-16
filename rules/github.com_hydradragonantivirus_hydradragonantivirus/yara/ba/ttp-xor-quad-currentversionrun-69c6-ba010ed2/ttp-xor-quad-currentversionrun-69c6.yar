rule TTP_XOR_QUAD_CurrentVersionRun_69c6 {
  strings:
    $key_69c6 = { 3a a9 [2] 1e a7 [2] 35 8b [2] 1b a9 [2] 0f b2 [2] 00 a8 [2] 1e b5 [2] 1c b4 [2] 07 b2 [2] 1b b5 [2] 07 9a }

  condition:
    any of them
}