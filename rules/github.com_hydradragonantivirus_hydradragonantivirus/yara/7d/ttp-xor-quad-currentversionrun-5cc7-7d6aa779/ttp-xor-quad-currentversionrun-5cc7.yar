rule TTP_XOR_QUAD_CurrentVersionRun_5cc7 {
  strings:
    $key_5cc7 = { 0f a8 [2] 2b a6 [2] 00 8a [2] 2e a8 [2] 3a b3 [2] 35 a9 [2] 2b b4 [2] 29 b5 [2] 32 b3 [2] 2e b4 [2] 32 9b }

  condition:
    any of them
}