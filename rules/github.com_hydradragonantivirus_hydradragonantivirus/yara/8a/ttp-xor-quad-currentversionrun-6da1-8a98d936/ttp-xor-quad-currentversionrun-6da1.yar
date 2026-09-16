rule TTP_XOR_QUAD_CurrentVersionRun_6da1 {
  strings:
    $key_6da1 = { 3e ce [2] 1a c0 [2] 31 ec [2] 1f ce [2] 0b d5 [2] 04 cf [2] 1a d2 [2] 18 d3 [2] 03 d5 [2] 1f d2 [2] 03 fd }

  condition:
    any of them
}