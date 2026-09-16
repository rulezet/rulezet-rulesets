rule TTP_XOR_QUAD_CurrentVersionRun_9da7 {
  strings:
    $key_9da7 = { ce c8 [2] ea c6 [2] c1 ea [2] ef c8 [2] fb d3 [2] f4 c9 [2] ea d4 [2] e8 d5 [2] f3 d3 [2] ef d4 [2] f3 fb }

  condition:
    any of them
}