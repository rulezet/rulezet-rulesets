rule TTP_XOR_QUAD_CurrentVersionRun_04a1 {
  strings:
    $key_04a1 = { 57 ce [2] 73 c0 [2] 58 ec [2] 76 ce [2] 62 d5 [2] 6d cf [2] 73 d2 [2] 71 d3 [2] 6a d5 [2] 76 d2 [2] 6a fd }

  condition:
    any of them
}