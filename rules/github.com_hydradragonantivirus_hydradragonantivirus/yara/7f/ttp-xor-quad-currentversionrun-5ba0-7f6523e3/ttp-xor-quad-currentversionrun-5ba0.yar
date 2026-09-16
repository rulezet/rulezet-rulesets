rule TTP_XOR_QUAD_CurrentVersionRun_5ba0 {
  strings:
    $key_5ba0 = { 08 cf [2] 2c c1 [2] 07 ed [2] 29 cf [2] 3d d4 [2] 32 ce [2] 2c d3 [2] 2e d2 [2] 35 d4 [2] 29 d3 [2] 35 fc }

  condition:
    any of them
}