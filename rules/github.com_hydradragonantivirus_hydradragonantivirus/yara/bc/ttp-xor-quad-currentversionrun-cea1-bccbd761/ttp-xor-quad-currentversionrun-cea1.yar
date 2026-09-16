rule TTP_XOR_QUAD_CurrentVersionRun_cea1 {
  strings:
    $key_cea1 = { 9d ce [2] b9 c0 [2] 92 ec [2] bc ce [2] a8 d5 [2] a7 cf [2] b9 d2 [2] bb d3 [2] a0 d5 [2] bc d2 [2] a0 fd }

  condition:
    any of them
}