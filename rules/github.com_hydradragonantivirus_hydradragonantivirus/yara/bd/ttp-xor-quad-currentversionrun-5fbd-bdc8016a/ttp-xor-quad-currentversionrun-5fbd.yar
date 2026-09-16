rule TTP_XOR_QUAD_CurrentVersionRun_5fbd {
  strings:
    $key_5fbd = { 0c d2 [2] 28 dc [2] 03 f0 [2] 2d d2 [2] 39 c9 [2] 36 d3 [2] 28 ce [2] 2a cf [2] 31 c9 [2] 2d ce [2] 31 e1 }

  condition:
    any of them
}