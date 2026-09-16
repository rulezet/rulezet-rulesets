rule TTP_XOR_QUAD_CurrentVersionRun_fea1 {
  strings:
    $key_fea1 = { ad ce [2] 89 c0 [2] a2 ec [2] 8c ce [2] 98 d5 [2] 97 cf [2] 89 d2 [2] 8b d3 [2] 90 d5 [2] 8c d2 [2] 90 fd }

  condition:
    any of them
}