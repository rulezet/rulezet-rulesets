rule TTP_XOR_QUAD_CurrentVersionRun_78a7 {
  strings:
    $key_78a7 = { 2b c8 [2] 0f c6 [2] 24 ea [2] 0a c8 [2] 1e d3 [2] 11 c9 [2] 0f d4 [2] 0d d5 [2] 16 d3 [2] 0a d4 [2] 16 fb }

  condition:
    any of them
}