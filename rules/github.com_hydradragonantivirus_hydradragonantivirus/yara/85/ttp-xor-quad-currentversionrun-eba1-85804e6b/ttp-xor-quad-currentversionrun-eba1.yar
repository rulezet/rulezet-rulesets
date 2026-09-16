rule TTP_XOR_QUAD_CurrentVersionRun_eba1 {
  strings:
    $key_eba1 = { b8 ce [2] 9c c0 [2] b7 ec [2] 99 ce [2] 8d d5 [2] 82 cf [2] 9c d2 [2] 9e d3 [2] 85 d5 [2] 99 d2 [2] 85 fd }

  condition:
    any of them
}