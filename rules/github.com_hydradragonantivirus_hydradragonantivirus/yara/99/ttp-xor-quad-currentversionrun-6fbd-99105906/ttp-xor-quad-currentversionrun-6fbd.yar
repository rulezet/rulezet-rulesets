rule TTP_XOR_QUAD_CurrentVersionRun_6fbd {
  strings:
    $key_6fbd = { 3c d2 [2] 18 dc [2] 33 f0 [2] 1d d2 [2] 09 c9 [2] 06 d3 [2] 18 ce [2] 1a cf [2] 01 c9 [2] 1d ce [2] 01 e1 }

  condition:
    any of them
}