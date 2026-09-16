rule TTP_XOR_QUAD_CurrentVersionRun_c3a1 {
  strings:
    $key_c3a1 = { 90 ce [2] b4 c0 [2] 9f ec [2] b1 ce [2] a5 d5 [2] aa cf [2] b4 d2 [2] b6 d3 [2] ad d5 [2] b1 d2 [2] ad fd }

  condition:
    any of them
}