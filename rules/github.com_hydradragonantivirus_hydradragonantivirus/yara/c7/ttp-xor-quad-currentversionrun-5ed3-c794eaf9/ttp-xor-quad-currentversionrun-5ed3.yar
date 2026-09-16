rule TTP_XOR_QUAD_CurrentVersionRun_5ed3 {
  strings:
    $key_5ed3 = { 0d bc [2] 29 b2 [2] 02 9e [2] 2c bc [2] 38 a7 [2] 37 bd [2] 29 a0 [2] 2b a1 [2] 30 a7 [2] 2c a0 [2] 30 8f }

  condition:
    any of them
}