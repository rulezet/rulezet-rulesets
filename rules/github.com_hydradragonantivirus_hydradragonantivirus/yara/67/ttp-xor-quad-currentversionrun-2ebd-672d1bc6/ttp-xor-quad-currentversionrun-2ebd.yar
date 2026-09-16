rule TTP_XOR_QUAD_CurrentVersionRun_2ebd {
  strings:
    $key_2ebd = { 7d d2 [2] 59 dc [2] 72 f0 [2] 5c d2 [2] 48 c9 [2] 47 d3 [2] 59 ce [2] 5b cf [2] 40 c9 [2] 5c ce [2] 40 e1 }

  condition:
    any of them
}