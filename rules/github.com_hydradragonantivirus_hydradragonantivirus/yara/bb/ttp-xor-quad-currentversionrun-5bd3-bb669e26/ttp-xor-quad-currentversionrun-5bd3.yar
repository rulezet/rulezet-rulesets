rule TTP_XOR_QUAD_CurrentVersionRun_5bd3 {
  strings:
    $key_5bd3 = { 08 bc [2] 2c b2 [2] 07 9e [2] 29 bc [2] 3d a7 [2] 32 bd [2] 2c a0 [2] 2e a1 [2] 35 a7 [2] 29 a0 [2] 35 8f }

  condition:
    any of them
}