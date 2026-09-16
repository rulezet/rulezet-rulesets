rule TTP_XOR_QUAD_CurrentVersionRun_70d3 {
  strings:
    $key_70d3 = { 23 bc [2] 07 b2 [2] 2c 9e [2] 02 bc [2] 16 a7 [2] 19 bd [2] 07 a0 [2] 05 a1 [2] 1e a7 [2] 02 a0 [2] 1e 8f }

  condition:
    any of them
}