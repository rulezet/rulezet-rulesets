rule TTP_XOR_QUAD_CurrentVersionRun_cfa1 {
  strings:
    $key_cfa1 = { 9c ce [2] b8 c0 [2] 93 ec [2] bd ce [2] a9 d5 [2] a6 cf [2] b8 d2 [2] ba d3 [2] a1 d5 [2] bd d2 [2] a1 fd }

  condition:
    any of them
}