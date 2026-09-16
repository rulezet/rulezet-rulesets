rule TTP_XOR_QUAD_CurrentVersionRun_eea1 {
  strings:
    $key_eea1 = { bd ce [2] 99 c0 [2] b2 ec [2] 9c ce [2] 88 d5 [2] 87 cf [2] 99 d2 [2] 9b d3 [2] 80 d5 [2] 9c d2 [2] 80 fd }

  condition:
    any of them
}