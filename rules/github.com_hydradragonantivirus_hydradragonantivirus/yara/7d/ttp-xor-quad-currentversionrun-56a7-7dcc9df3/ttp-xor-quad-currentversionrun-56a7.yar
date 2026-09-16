rule TTP_XOR_QUAD_CurrentVersionRun_56a7 {
  strings:
    $key_56a7 = { 05 c8 [2] 21 c6 [2] 0a ea [2] 24 c8 [2] 30 d3 [2] 3f c9 [2] 21 d4 [2] 23 d5 [2] 38 d3 [2] 24 d4 [2] 38 fb }

  condition:
    any of them
}