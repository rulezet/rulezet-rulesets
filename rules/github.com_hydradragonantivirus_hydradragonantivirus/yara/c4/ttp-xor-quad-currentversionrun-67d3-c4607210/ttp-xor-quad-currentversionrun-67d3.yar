rule TTP_XOR_QUAD_CurrentVersionRun_67d3 {
  strings:
    $key_67d3 = { 34 bc [2] 10 b2 [2] 3b 9e [2] 15 bc [2] 01 a7 [2] 0e bd [2] 10 a0 [2] 12 a1 [2] 09 a7 [2] 15 a0 [2] 09 8f }

  condition:
    any of them
}