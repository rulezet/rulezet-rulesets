rule TTP_XOR_QUAD_CurrentVersionRun_9fa1 {
  strings:
    $key_9fa1 = { cc ce [2] e8 c0 [2] c3 ec [2] ed ce [2] f9 d5 [2] f6 cf [2] e8 d2 [2] ea d3 [2] f1 d5 [2] ed d2 [2] f1 fd }

  condition:
    any of them
}