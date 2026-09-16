rule TTP_XOR_QUAD_CurrentVersionRun_c1a7 {
  strings:
    $key_c1a7 = { 92 c8 [2] b6 c6 [2] 9d ea [2] b3 c8 [2] a7 d3 [2] a8 c9 [2] b6 d4 [2] b4 d5 [2] af d3 [2] b3 d4 [2] af fb }

  condition:
    any of them
}