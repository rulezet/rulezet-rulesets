rule TTP_XOR_QUAD_CurrentVersionRun_81a7 {
  strings:
    $key_81a7 = { d2 c8 [2] f6 c6 [2] dd ea [2] f3 c8 [2] e7 d3 [2] e8 c9 [2] f6 d4 [2] f4 d5 [2] ef d3 [2] f3 d4 [2] ef fb }

  condition:
    any of them
}