rule TTP_XOR_QUAD_CurrentVersionRun_59c6 {
  strings:
    $key_59c6 = { 0a a9 [2] 2e a7 [2] 05 8b [2] 2b a9 [2] 3f b2 [2] 30 a8 [2] 2e b5 [2] 2c b4 [2] 37 b2 [2] 2b b5 [2] 37 9a }

  condition:
    any of them
}