rule TTP_XOR_QUAD_CurrentVersionRun_2fd3 {
  strings:
    $key_2fd3 = { 7c bc [2] 58 b2 [2] 73 9e [2] 5d bc [2] 49 a7 [2] 46 bd [2] 58 a0 [2] 5a a1 [2] 41 a7 [2] 5d a0 [2] 41 8f }

  condition:
    any of them
}