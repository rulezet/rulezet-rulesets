rule TTP_XOR_QUAD_CurrentVersionRun_5cc6 {
  strings:
    $key_5cc6 = { 0f a9 [2] 2b a7 [2] 00 8b [2] 2e a9 [2] 3a b2 [2] 35 a8 [2] 2b b5 [2] 29 b4 [2] 32 b2 [2] 2e b5 [2] 32 9a }

  condition:
    any of them
}