rule TTP_XOR_QUAD_CurrentVersionRun_59c7 {
  strings:
    $key_59c7 = { 0a a8 [2] 2e a6 [2] 05 8a [2] 2b a8 [2] 3f b3 [2] 30 a9 [2] 2e b4 [2] 2c b5 [2] 37 b3 [2] 2b b4 [2] 37 9b }

  condition:
    any of them
}