rule TTP_XOR_QUAD_CurrentVersionRun_78a1 {
  strings:
    $key_78a1 = { 2b ce [2] 0f c0 [2] 24 ec [2] 0a ce [2] 1e d5 [2] 11 cf [2] 0f d2 [2] 0d d3 [2] 16 d5 [2] 0a d2 [2] 16 fd }

  condition:
    any of them
}