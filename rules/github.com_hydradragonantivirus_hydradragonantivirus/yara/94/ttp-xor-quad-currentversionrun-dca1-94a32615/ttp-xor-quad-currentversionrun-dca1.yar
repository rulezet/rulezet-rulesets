rule TTP_XOR_QUAD_CurrentVersionRun_dca1 {
  strings:
    $key_dca1 = { 8f ce [2] ab c0 [2] 80 ec [2] ae ce [2] ba d5 [2] b5 cf [2] ab d2 [2] a9 d3 [2] b2 d5 [2] ae d2 [2] b2 fd }

  condition:
    any of them
}