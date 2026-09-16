rule TTP_XOR_QUAD_CurrentVersionRun_17a1 {
  strings:
    $key_17a1 = { 44 ce [2] 60 c0 [2] 4b ec [2] 65 ce [2] 71 d5 [2] 7e cf [2] 60 d2 [2] 62 d3 [2] 79 d5 [2] 65 d2 [2] 79 fd }

  condition:
    any of them
}