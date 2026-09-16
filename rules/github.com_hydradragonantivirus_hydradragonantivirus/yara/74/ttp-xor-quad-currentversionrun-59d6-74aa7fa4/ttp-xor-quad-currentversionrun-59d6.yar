rule TTP_XOR_QUAD_CurrentVersionRun_59d6 {
  strings:
    $key_59d6 = { 0a b9 [2] 2e b7 [2] 05 9b [2] 2b b9 [2] 3f a2 [2] 30 b8 [2] 2e a5 [2] 2c a4 [2] 37 a2 [2] 2b a5 [2] 37 8a }

  condition:
    any of them
}