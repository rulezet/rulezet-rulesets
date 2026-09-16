rule TTP_XOR_QUAD_CurrentVersionRun_60bd {
  strings:
    $key_60bd = { 33 d2 [2] 17 dc [2] 3c f0 [2] 12 d2 [2] 06 c9 [2] 09 d3 [2] 17 ce [2] 15 cf [2] 0e c9 [2] 12 ce [2] 0e e1 }

  condition:
    any of them
}