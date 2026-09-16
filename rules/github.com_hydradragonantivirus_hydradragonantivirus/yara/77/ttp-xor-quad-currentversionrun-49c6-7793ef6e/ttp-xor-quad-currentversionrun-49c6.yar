rule TTP_XOR_QUAD_CurrentVersionRun_49c6 {
  strings:
    $key_49c6 = { 1a a9 [2] 3e a7 [2] 15 8b [2] 3b a9 [2] 2f b2 [2] 20 a8 [2] 3e b5 [2] 3c b4 [2] 27 b2 [2] 3b b5 [2] 27 9a }

  condition:
    any of them
}