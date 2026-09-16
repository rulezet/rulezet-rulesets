rule TTP_XOR_QUAD_CurrentVersionRun_9ea7 {
  strings:
    $key_9ea7 = { cd c8 [2] e9 c6 [2] c2 ea [2] ec c8 [2] f8 d3 [2] f7 c9 [2] e9 d4 [2] eb d5 [2] f0 d3 [2] ec d4 [2] f0 fb }

  condition:
    any of them
}