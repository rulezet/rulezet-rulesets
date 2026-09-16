rule TTP_XOR_QUAD_CurrentVersionRun_7fd3 {
  strings:
    $key_7fd3 = { 2c bc [2] 08 b2 [2] 23 9e [2] 0d bc [2] 19 a7 [2] 16 bd [2] 08 a0 [2] 0a a1 [2] 11 a7 [2] 0d a0 [2] 11 8f }

  condition:
    any of them
}