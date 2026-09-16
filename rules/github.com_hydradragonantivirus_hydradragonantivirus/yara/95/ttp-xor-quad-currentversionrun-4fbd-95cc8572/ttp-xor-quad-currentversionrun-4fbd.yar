rule TTP_XOR_QUAD_CurrentVersionRun_4fbd {
  strings:
    $key_4fbd = { 1c d2 [2] 38 dc [2] 13 f0 [2] 3d d2 [2] 29 c9 [2] 26 d3 [2] 38 ce [2] 3a cf [2] 21 c9 [2] 3d ce [2] 21 e1 }

  condition:
    any of them
}