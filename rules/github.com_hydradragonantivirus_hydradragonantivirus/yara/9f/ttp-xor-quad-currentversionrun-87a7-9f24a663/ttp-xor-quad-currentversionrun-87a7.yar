rule TTP_XOR_QUAD_CurrentVersionRun_87a7 {
  strings:
    $key_87a7 = { d4 c8 [2] f0 c6 [2] db ea [2] f5 c8 [2] e1 d3 [2] ee c9 [2] f0 d4 [2] f2 d5 [2] e9 d3 [2] f5 d4 [2] e9 fb }

  condition:
    any of them
}