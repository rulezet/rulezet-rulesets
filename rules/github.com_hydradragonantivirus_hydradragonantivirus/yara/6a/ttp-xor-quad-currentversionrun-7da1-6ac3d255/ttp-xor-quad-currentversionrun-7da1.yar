rule TTP_XOR_QUAD_CurrentVersionRun_7da1 {
  strings:
    $key_7da1 = { 2e ce [2] 0a c0 [2] 21 ec [2] 0f ce [2] 1b d5 [2] 14 cf [2] 0a d2 [2] 08 d3 [2] 13 d5 [2] 0f d2 [2] 13 fd }

  condition:
    any of them
}