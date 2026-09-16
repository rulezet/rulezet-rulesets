rule TTP_XOR_QUAD_CurrentVersionRun_99a7 {
  strings:
    $key_99a7 = { ca c8 [2] ee c6 [2] c5 ea [2] eb c8 [2] ff d3 [2] f0 c9 [2] ee d4 [2] ec d5 [2] f7 d3 [2] eb d4 [2] f7 fb }

  condition:
    any of them
}