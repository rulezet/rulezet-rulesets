rule TTP_XOR_QUAD_CurrentVersionRun_1da1 {
  strings:
    $key_1da1 = { 4e ce [2] 6a c0 [2] 41 ec [2] 6f ce [2] 7b d5 [2] 74 cf [2] 6a d2 [2] 68 d3 [2] 73 d5 [2] 6f d2 [2] 73 fd }

  condition:
    any of them
}