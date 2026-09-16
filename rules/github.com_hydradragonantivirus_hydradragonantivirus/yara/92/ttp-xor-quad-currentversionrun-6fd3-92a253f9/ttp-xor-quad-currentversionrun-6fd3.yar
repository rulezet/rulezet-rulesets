rule TTP_XOR_QUAD_CurrentVersionRun_6fd3 {
  strings:
    $key_6fd3 = { 3c bc [2] 18 b2 [2] 33 9e [2] 1d bc [2] 09 a7 [2] 06 bd [2] 18 a0 [2] 1a a1 [2] 01 a7 [2] 1d a0 [2] 01 8f }

  condition:
    any of them
}