rule TTP_XOR_QUAD_CurrentVersionRun_d3a7 {
  strings:
    $key_d3a7 = { 80 c8 [2] a4 c6 [2] 8f ea [2] a1 c8 [2] b5 d3 [2] ba c9 [2] a4 d4 [2] a6 d5 [2] bd d3 [2] a1 d4 [2] bd fb }

  condition:
    any of them
}