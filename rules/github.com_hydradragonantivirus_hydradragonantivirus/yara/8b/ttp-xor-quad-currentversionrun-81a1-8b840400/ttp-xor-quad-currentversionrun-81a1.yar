rule TTP_XOR_QUAD_CurrentVersionRun_81a1 {
  strings:
    $key_81a1 = { d2 ce [2] f6 c0 [2] dd ec [2] f3 ce [2] e7 d5 [2] e8 cf [2] f6 d2 [2] f4 d3 [2] ef d5 [2] f3 d2 [2] ef fd }

  condition:
    any of them
}