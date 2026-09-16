rule TTP_XOR_QUAD_CurrentVersionRun_eebd {
  strings:
    $key_eebd = { bd d2 [2] 99 dc [2] b2 f0 [2] 9c d2 [2] 88 c9 [2] 87 d3 [2] 99 ce [2] 9b cf [2] 80 c9 [2] 9c ce [2] 80 e1 }

  condition:
    any of them
}