rule TTP_XOR_QUAD_CurrentVersionRun_5cd3 {
  strings:
    $key_5cd3 = { 0f bc [2] 2b b2 [2] 00 9e [2] 2e bc [2] 3a a7 [2] 35 bd [2] 2b a0 [2] 29 a1 [2] 32 a7 [2] 2e a0 [2] 32 8f }

  condition:
    any of them
}