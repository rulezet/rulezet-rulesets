rule TTP_XOR_QUAD_CurrentVersionRun_74a1 {
  strings:
    $key_74a1 = { 27 ce [2] 03 c0 [2] 28 ec [2] 06 ce [2] 12 d5 [2] 1d cf [2] 03 d2 [2] 01 d3 [2] 1a d5 [2] 06 d2 [2] 1a fd }

  condition:
    any of them
}