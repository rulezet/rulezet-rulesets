rule TTP_XOR_QUAD_CurrentVersionRun_6ed3 {
  strings:
    $key_6ed3 = { 3d bc [2] 19 b2 [2] 32 9e [2] 1c bc [2] 08 a7 [2] 07 bd [2] 19 a0 [2] 1b a1 [2] 00 a7 [2] 1c a0 [2] 00 8f }

  condition:
    any of them
}