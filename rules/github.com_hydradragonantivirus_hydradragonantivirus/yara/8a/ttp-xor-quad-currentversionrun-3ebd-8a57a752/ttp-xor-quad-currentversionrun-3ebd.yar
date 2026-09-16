rule TTP_XOR_QUAD_CurrentVersionRun_3ebd {
  strings:
    $key_3ebd = { 6d d2 [2] 49 dc [2] 62 f0 [2] 4c d2 [2] 58 c9 [2] 57 d3 [2] 49 ce [2] 4b cf [2] 50 c9 [2] 4c ce [2] 50 e1 }

  condition:
    any of them
}