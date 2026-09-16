rule TTP_XOR_QUAD_CurrentVersionRun_1cd3 {
  strings:
    $key_1cd3 = { 4f bc [2] 6b b2 [2] 40 9e [2] 6e bc [2] 7a a7 [2] 75 bd [2] 6b a0 [2] 69 a1 [2] 72 a7 [2] 6e a0 [2] 72 8f }

  condition:
    any of them
}