rule TTP_XOR_QUAD_CurrentVersionRun_ecd3 {
  strings:
    $key_ecd3 = { bf bc [2] 9b b2 [2] b0 9e [2] 9e bc [2] 8a a7 [2] 85 bd [2] 9b a0 [2] 99 a1 [2] 82 a7 [2] 9e a0 [2] 82 8f }

  condition:
    any of them
}