rule TTP_XOR_QUAD_CurrentVersionRun_0ca7 {
  strings:
    $key_0ca7 = { 5f c8 [2] 7b c6 [2] 50 ea [2] 7e c8 [2] 6a d3 [2] 65 c9 [2] 7b d4 [2] 79 d5 [2] 62 d3 [2] 7e d4 [2] 62 fb }

  condition:
    any of them
}