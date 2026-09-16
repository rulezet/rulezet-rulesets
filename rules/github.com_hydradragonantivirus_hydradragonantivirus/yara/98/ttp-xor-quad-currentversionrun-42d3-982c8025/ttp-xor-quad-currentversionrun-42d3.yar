rule TTP_XOR_QUAD_CurrentVersionRun_42d3 {
  strings:
    $key_42d3 = { 11 bc [2] 35 b2 [2] 1e 9e [2] 30 bc [2] 24 a7 [2] 2b bd [2] 35 a0 [2] 37 a1 [2] 2c a7 [2] 30 a0 [2] 2c 8f }

  condition:
    any of them
}