rule TTP_XOR_QUAD_CurrentVersionRun_96a1 {
  strings:
    $key_96a1 = { c5 ce [2] e1 c0 [2] ca ec [2] e4 ce [2] f0 d5 [2] ff cf [2] e1 d2 [2] e3 d3 [2] f8 d5 [2] e4 d2 [2] f8 fd }

  condition:
    any of them
}