rule TTP_XOR_QUAD_CurrentVersionRun_5fd3 {
  strings:
    $key_5fd3 = { 0c bc [2] 28 b2 [2] 03 9e [2] 2d bc [2] 39 a7 [2] 36 bd [2] 28 a0 [2] 2a a1 [2] 31 a7 [2] 2d a0 [2] 31 8f }

  condition:
    any of them
}