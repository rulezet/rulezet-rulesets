rule TTP_XOR_QUAD_CurrentVersionRun_afa1 {
  strings:
    $key_afa1 = { fc ce [2] d8 c0 [2] f3 ec [2] dd ce [2] c9 d5 [2] c6 cf [2] d8 d2 [2] da d3 [2] c1 d5 [2] dd d2 [2] c1 fd }

  condition:
    any of them
}