rule TTP_XOR_QUAD_CurrentVersionRun_42bd {
  strings:
    $key_42bd = { 11 d2 [2] 35 dc [2] 1e f0 [2] 30 d2 [2] 24 c9 [2] 2b d3 [2] 35 ce [2] 37 cf [2] 2c c9 [2] 30 ce [2] 2c e1 }

  condition:
    any of them
}