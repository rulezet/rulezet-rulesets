rule TTP_XOR_QUAD_CurrentVersionRun_6ebd {
  strings:
    $key_6ebd = { 3d d2 [2] 19 dc [2] 32 f0 [2] 1c d2 [2] 08 c9 [2] 07 d3 [2] 19 ce [2] 1b cf [2] 00 c9 [2] 1c ce [2] 00 e1 }

  condition:
    any of them
}