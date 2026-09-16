rule TTP_XOR_QUAD_CurrentVersionRun_45bd {
  strings:
    $key_45bd = { 16 d2 [2] 32 dc [2] 19 f0 [2] 37 d2 [2] 23 c9 [2] 2c d3 [2] 32 ce [2] 30 cf [2] 2b c9 [2] 37 ce [2] 2b e1 }

  condition:
    any of them
}