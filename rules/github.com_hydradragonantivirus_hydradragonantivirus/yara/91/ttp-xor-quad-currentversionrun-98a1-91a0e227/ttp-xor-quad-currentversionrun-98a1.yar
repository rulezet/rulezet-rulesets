rule TTP_XOR_QUAD_CurrentVersionRun_98a1 {
  strings:
    $key_98a1 = { cb ce [2] ef c0 [2] c4 ec [2] ea ce [2] fe d5 [2] f1 cf [2] ef d2 [2] ed d3 [2] f6 d5 [2] ea d2 [2] f6 fd }

  condition:
    any of them
}