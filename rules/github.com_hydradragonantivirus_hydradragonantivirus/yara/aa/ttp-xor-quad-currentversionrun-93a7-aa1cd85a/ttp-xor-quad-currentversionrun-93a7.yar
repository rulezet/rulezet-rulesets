rule TTP_XOR_QUAD_CurrentVersionRun_93a7 {
  strings:
    $key_93a7 = { c0 c8 [2] e4 c6 [2] cf ea [2] e1 c8 [2] f5 d3 [2] fa c9 [2] e4 d4 [2] e6 d5 [2] fd d3 [2] e1 d4 [2] fd fb }

  condition:
    any of them
}