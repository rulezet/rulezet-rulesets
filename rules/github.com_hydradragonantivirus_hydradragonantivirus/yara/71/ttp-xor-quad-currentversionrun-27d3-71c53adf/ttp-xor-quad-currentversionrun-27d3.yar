rule TTP_XOR_QUAD_CurrentVersionRun_27d3 {
  strings:
    $key_27d3 = { 74 bc [2] 50 b2 [2] 7b 9e [2] 55 bc [2] 41 a7 [2] 4e bd [2] 50 a0 [2] 52 a1 [2] 49 a7 [2] 55 a0 [2] 49 8f }

  condition:
    any of them
}