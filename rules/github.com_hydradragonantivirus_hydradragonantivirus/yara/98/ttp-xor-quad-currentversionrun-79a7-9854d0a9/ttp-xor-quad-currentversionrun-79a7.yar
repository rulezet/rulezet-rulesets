rule TTP_XOR_QUAD_CurrentVersionRun_79a7 {
  strings:
    $key_79a7 = { 2a c8 [2] 0e c6 [2] 25 ea [2] 0b c8 [2] 1f d3 [2] 10 c9 [2] 0e d4 [2] 0c d5 [2] 17 d3 [2] 0b d4 [2] 17 fb }

  condition:
    any of them
}