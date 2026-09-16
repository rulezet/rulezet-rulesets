rule TTP_XOR_QUAD_CurrentVersionRun_74d3 {
  strings:
    $key_74d3 = { 27 bc [2] 03 b2 [2] 28 9e [2] 06 bc [2] 12 a7 [2] 1d bd [2] 03 a0 [2] 01 a1 [2] 1a a7 [2] 06 a0 [2] 1a 8f }

  condition:
    any of them
}