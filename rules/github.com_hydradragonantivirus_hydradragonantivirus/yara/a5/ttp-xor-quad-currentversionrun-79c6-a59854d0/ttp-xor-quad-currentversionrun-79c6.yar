rule TTP_XOR_QUAD_CurrentVersionRun_79c6 {
  strings:
    $key_79c6 = { 2a a9 [2] 0e a7 [2] 25 8b [2] 0b a9 [2] 1f b2 [2] 10 a8 [2] 0e b5 [2] 0c b4 [2] 17 b2 [2] 0b b5 [2] 17 9a }

  condition:
    any of them
}