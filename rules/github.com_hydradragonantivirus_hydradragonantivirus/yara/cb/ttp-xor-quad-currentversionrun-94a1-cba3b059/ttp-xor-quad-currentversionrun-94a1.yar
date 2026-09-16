rule TTP_XOR_QUAD_CurrentVersionRun_94a1 {
  strings:
    $key_94a1 = { c7 ce [2] e3 c0 [2] c8 ec [2] e6 ce [2] f2 d5 [2] fd cf [2] e3 d2 [2] e1 d3 [2] fa d5 [2] e6 d2 [2] fa fd }

  condition:
    any of them
}