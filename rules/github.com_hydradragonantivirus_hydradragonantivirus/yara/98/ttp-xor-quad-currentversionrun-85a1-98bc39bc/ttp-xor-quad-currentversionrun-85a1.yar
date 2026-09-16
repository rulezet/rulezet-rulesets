rule TTP_XOR_QUAD_CurrentVersionRun_85a1 {
  strings:
    $key_85a1 = { d6 ce [2] f2 c0 [2] d9 ec [2] f7 ce [2] e3 d5 [2] ec cf [2] f2 d2 [2] f0 d3 [2] eb d5 [2] f7 d2 [2] eb fd }

  condition:
    any of them
}