rule TTP_XOR_QUAD_CurrentVersionRun_69a7 {
  strings:
    $key_69a7 = { 3a c8 [2] 1e c6 [2] 35 ea [2] 1b c8 [2] 0f d3 [2] 00 c9 [2] 1e d4 [2] 1c d5 [2] 07 d3 [2] 1b d4 [2] 07 fb }

  condition:
    any of them
}