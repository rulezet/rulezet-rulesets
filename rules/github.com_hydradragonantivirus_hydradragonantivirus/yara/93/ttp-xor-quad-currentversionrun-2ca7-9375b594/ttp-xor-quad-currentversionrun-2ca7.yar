rule TTP_XOR_QUAD_CurrentVersionRun_2ca7 {
  strings:
    $key_2ca7 = { 7f c8 [2] 5b c6 [2] 70 ea [2] 5e c8 [2] 4a d3 [2] 45 c9 [2] 5b d4 [2] 59 d5 [2] 42 d3 [2] 5e d4 [2] 42 fb }

  condition:
    any of them
}