rule TTP_XOR_QUAD_CurrentVersionRun_7cd3 {
  strings:
    $key_7cd3 = { 2f bc [2] 0b b2 [2] 20 9e [2] 0e bc [2] 1a a7 [2] 15 bd [2] 0b a0 [2] 09 a1 [2] 12 a7 [2] 0e a0 [2] 12 8f }

  condition:
    any of them
}