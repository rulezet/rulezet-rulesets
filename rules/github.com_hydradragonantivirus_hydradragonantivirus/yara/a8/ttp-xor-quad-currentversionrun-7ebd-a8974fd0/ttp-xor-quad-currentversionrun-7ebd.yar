rule TTP_XOR_QUAD_CurrentVersionRun_7ebd {
  strings:
    $key_7ebd = { 2d d2 [2] 09 dc [2] 22 f0 [2] 0c d2 [2] 18 c9 [2] 17 d3 [2] 09 ce [2] 0b cf [2] 10 c9 [2] 0c ce [2] 10 e1 }

  condition:
    any of them
}