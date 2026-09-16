rule TTP_XOR_QUAD_CurrentVersionRun_4ad3 {
  strings:
    $key_4ad3 = { 19 bc [2] 3d b2 [2] 16 9e [2] 38 bc [2] 2c a7 [2] 23 bd [2] 3d a0 [2] 3f a1 [2] 24 a7 [2] 38 a0 [2] 24 8f }

  condition:
    any of them
}