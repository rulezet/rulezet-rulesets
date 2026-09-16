rule TTP_XOR_QUAD_CurrentVersionRun_15a1 {
  strings:
    $key_15a1 = { 46 ce [2] 62 c0 [2] 49 ec [2] 67 ce [2] 73 d5 [2] 7c cf [2] 62 d2 [2] 60 d3 [2] 7b d5 [2] 67 d2 [2] 7b fd }

  condition:
    any of them
}