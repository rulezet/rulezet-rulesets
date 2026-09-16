rule TTP_XOR_QUAD_CurrentVersionRun_08a1 {
  strings:
    $key_08a1 = { 5b ce [2] 7f c0 [2] 54 ec [2] 7a ce [2] 6e d5 [2] 61 cf [2] 7f d2 [2] 7d d3 [2] 66 d5 [2] 7a d2 [2] 66 fd }

  condition:
    any of them
}