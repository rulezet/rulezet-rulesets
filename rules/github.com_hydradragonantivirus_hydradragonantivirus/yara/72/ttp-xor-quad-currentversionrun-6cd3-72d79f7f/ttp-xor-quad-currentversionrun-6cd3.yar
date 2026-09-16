rule TTP_XOR_QUAD_CurrentVersionRun_6cd3 {
  strings:
    $key_6cd3 = { 3f bc [2] 1b b2 [2] 30 9e [2] 1e bc [2] 0a a7 [2] 05 bd [2] 1b a0 [2] 19 a1 [2] 02 a7 [2] 1e a0 [2] 02 8f }

  condition:
    any of them
}