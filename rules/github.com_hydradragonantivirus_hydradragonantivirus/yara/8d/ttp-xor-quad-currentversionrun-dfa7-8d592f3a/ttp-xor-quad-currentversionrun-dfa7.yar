rule TTP_XOR_QUAD_CurrentVersionRun_dfa7 {
  strings:
    $key_dfa7 = { 8c c8 [2] a8 c6 [2] 83 ea [2] ad c8 [2] b9 d3 [2] b6 c9 [2] a8 d4 [2] aa d5 [2] b1 d3 [2] ad d4 [2] b1 fb }

  condition:
    any of them
}