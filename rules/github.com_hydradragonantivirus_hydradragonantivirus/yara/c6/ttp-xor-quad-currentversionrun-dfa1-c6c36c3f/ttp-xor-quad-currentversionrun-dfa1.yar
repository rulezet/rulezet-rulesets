rule TTP_XOR_QUAD_CurrentVersionRun_dfa1 {
  strings:
    $key_dfa1 = { 8c ce [2] a8 c0 [2] 83 ec [2] ad ce [2] b9 d5 [2] b6 cf [2] a8 d2 [2] aa d3 [2] b1 d5 [2] ad d2 [2] b1 fd }

  condition:
    any of them
}