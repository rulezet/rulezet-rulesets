rule TTP_XOR_QUAD_CurrentVersionRun_06a1 {
  strings:
    $key_06a1 = { 55 ce [2] 71 c0 [2] 5a ec [2] 74 ce [2] 60 d5 [2] 6f cf [2] 71 d2 [2] 73 d3 [2] 68 d5 [2] 74 d2 [2] 68 fd }

  condition:
    any of them
}