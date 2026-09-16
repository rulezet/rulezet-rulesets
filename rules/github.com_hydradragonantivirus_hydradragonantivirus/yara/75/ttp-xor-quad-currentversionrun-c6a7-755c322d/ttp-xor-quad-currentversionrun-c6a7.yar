rule TTP_XOR_QUAD_CurrentVersionRun_c6a7 {
  strings:
    $key_c6a7 = { 95 c8 [2] b1 c6 [2] 9a ea [2] b4 c8 [2] a0 d3 [2] af c9 [2] b1 d4 [2] b3 d5 [2] a8 d3 [2] b4 d4 [2] a8 fb }

  condition:
    any of them
}