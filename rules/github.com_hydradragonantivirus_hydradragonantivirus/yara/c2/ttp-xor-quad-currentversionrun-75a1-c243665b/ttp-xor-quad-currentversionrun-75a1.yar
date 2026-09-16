rule TTP_XOR_QUAD_CurrentVersionRun_75a1 {
  strings:
    $key_75a1 = { 26 ce [2] 02 c0 [2] 29 ec [2] 07 ce [2] 13 d5 [2] 1c cf [2] 02 d2 [2] 00 d3 [2] 1b d5 [2] 07 d2 [2] 1b fd }

  condition:
    any of them
}