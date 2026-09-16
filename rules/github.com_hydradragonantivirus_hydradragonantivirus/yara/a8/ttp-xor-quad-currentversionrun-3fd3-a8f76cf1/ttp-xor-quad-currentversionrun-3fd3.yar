rule TTP_XOR_QUAD_CurrentVersionRun_3fd3 {
  strings:
    $key_3fd3 = { 6c bc [2] 48 b2 [2] 63 9e [2] 4d bc [2] 59 a7 [2] 56 bd [2] 48 a0 [2] 4a a1 [2] 51 a7 [2] 4d a0 [2] 51 8f }

  condition:
    any of them
}