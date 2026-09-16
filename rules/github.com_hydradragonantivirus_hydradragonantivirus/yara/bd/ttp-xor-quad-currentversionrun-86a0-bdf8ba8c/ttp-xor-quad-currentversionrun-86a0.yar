rule TTP_XOR_QUAD_CurrentVersionRun_86a0 {
  strings:
    $key_86a0 = { d5 cf [2] f1 c1 [2] da ed [2] f4 cf [2] e0 d4 [2] ef ce [2] f1 d3 [2] f3 d2 [2] e8 d4 [2] f4 d3 [2] e8 fc }

  condition:
    any of them
}