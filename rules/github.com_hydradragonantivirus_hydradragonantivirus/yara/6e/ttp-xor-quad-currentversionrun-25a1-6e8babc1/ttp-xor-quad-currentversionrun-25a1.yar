rule TTP_XOR_QUAD_CurrentVersionRun_25a1 {
  strings:
    $key_25a1 = { 76 ce [2] 52 c0 [2] 79 ec [2] 57 ce [2] 43 d5 [2] 4c cf [2] 52 d2 [2] 50 d3 [2] 4b d5 [2] 57 d2 [2] 4b fd }

  condition:
    any of them
}