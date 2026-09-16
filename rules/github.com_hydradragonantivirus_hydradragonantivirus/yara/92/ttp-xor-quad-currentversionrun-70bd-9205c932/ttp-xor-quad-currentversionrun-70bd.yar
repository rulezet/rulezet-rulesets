rule TTP_XOR_QUAD_CurrentVersionRun_70bd {
  strings:
    $key_70bd = { 23 d2 [2] 07 dc [2] 2c f0 [2] 02 d2 [2] 16 c9 [2] 19 d3 [2] 07 ce [2] 05 cf [2] 1e c9 [2] 02 ce [2] 1e e1 }

  condition:
    any of them
}