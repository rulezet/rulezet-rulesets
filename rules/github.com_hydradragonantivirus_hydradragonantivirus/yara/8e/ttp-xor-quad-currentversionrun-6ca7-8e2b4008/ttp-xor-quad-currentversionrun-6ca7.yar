rule TTP_XOR_QUAD_CurrentVersionRun_6ca7 {
  strings:
    $key_6ca7 = { 3f c8 [2] 1b c6 [2] 30 ea [2] 1e c8 [2] 0a d3 [2] 05 c9 [2] 1b d4 [2] 19 d5 [2] 02 d3 [2] 1e d4 [2] 02 fb }

  condition:
    any of them
}