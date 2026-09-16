rule TTP_XOR_QUAD_CurrentVersionRun_d4a7 {
  strings:
    $key_d4a7 = { 87 c8 [2] a3 c6 [2] 88 ea [2] a6 c8 [2] b2 d3 [2] bd c9 [2] a3 d4 [2] a1 d5 [2] ba d3 [2] a6 d4 [2] ba fb }

  condition:
    any of them
}