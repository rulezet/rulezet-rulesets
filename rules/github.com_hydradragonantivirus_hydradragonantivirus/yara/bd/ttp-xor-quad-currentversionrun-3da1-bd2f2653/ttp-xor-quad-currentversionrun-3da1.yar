rule TTP_XOR_QUAD_CurrentVersionRun_3da1 {
  strings:
    $key_3da1 = { 6e ce [2] 4a c0 [2] 61 ec [2] 4f ce [2] 5b d5 [2] 54 cf [2] 4a d2 [2] 48 d3 [2] 53 d5 [2] 4f d2 [2] 53 fd }

  condition:
    any of them
}