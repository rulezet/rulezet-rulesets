rule TTP_XOR_QUAD_CurrentVersionRun_99b2 {
  strings:
    $key_99b2 = { ca dd [2] ee d3 [2] c5 ff [2] eb dd [2] ff c6 [2] f0 dc [2] ee c1 [2] ec c0 [2] f7 c6 [2] eb c1 [2] f7 ee }

  condition:
    any of them
}