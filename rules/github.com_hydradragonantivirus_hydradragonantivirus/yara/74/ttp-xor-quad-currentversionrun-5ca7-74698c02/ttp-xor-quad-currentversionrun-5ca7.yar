rule TTP_XOR_QUAD_CurrentVersionRun_5ca7 {
  strings:
    $key_5ca7 = { 0f c8 [2] 2b c6 [2] 00 ea [2] 2e c8 [2] 3a d3 [2] 35 c9 [2] 2b d4 [2] 29 d5 [2] 32 d3 [2] 2e d4 [2] 32 fb }

  condition:
    any of them
}