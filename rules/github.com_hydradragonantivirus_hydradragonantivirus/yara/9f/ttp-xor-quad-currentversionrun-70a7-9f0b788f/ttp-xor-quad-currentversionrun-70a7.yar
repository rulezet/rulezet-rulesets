rule TTP_XOR_QUAD_CurrentVersionRun_70a7 {
  strings:
    $key_70a7 = { 23 c8 [2] 07 c6 [2] 2c ea [2] 02 c8 [2] 16 d3 [2] 19 c9 [2] 07 d4 [2] 05 d5 [2] 1e d3 [2] 02 d4 [2] 1e fb }

  condition:
    any of them
}