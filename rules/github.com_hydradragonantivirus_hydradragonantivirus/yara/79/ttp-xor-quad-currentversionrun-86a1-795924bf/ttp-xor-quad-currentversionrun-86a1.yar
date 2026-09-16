rule TTP_XOR_QUAD_CurrentVersionRun_86a1 {
  strings:
    $key_86a1 = { d5 ce [2] f1 c0 [2] da ec [2] f4 ce [2] e0 d5 [2] ef cf [2] f1 d2 [2] f3 d3 [2] e8 d5 [2] f4 d2 [2] e8 fd }

  condition:
    any of them
}