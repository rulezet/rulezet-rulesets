rule TTP_XOR_QUAD_CurrentVersionRun_3ed3 {
  strings:
    $key_3ed3 = { 6d bc [2] 49 b2 [2] 62 9e [2] 4c bc [2] 58 a7 [2] 57 bd [2] 49 a0 [2] 4b a1 [2] 50 a7 [2] 4c a0 [2] 50 8f }

  condition:
    any of them
}