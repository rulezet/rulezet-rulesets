rule TTP_XOR_QUAD_CurrentVersionRun_5ba1 {
  strings:
    $key_5ba1 = { 08 ce [2] 2c c0 [2] 07 ec [2] 29 ce [2] 3d d5 [2] 32 cf [2] 2c d2 [2] 2e d3 [2] 35 d5 [2] 29 d2 [2] 35 fd }

  condition:
    any of them
}