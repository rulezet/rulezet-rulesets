rule TTP_XOR_QUAD_CurrentVersionRun_49c7 {
  strings:
    $key_49c7 = { 1a a8 [2] 3e a6 [2] 15 8a [2] 3b a8 [2] 2f b3 [2] 20 a9 [2] 3e b4 [2] 3c b5 [2] 27 b3 [2] 3b b4 [2] 27 9b }

  condition:
    any of them
}