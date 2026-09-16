rule TTP_XOR_QUAD_CurrentVersionRun_59a7 {
  strings:
    $key_59a7 = { 0a c8 [2] 2e c6 [2] 05 ea [2] 2b c8 [2] 3f d3 [2] 30 c9 [2] 2e d4 [2] 2c d5 [2] 37 d3 [2] 2b d4 [2] 37 fb }

  condition:
    any of them
}