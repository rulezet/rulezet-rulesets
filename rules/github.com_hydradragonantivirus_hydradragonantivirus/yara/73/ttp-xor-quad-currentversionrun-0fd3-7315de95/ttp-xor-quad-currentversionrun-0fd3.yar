rule TTP_XOR_QUAD_CurrentVersionRun_0fd3 {
  strings:
    $key_0fd3 = { 5c bc [2] 78 b2 [2] 53 9e [2] 7d bc [2] 69 a7 [2] 66 bd [2] 78 a0 [2] 7a a1 [2] 61 a7 [2] 7d a0 [2] 61 8f }

  condition:
    any of them
}