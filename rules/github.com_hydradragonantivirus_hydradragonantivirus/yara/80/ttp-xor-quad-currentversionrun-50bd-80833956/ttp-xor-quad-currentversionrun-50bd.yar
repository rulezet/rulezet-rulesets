rule TTP_XOR_QUAD_CurrentVersionRun_50bd {
  strings:
    $key_50bd = { 03 d2 [2] 27 dc [2] 0c f0 [2] 22 d2 [2] 36 c9 [2] 39 d3 [2] 27 ce [2] 25 cf [2] 3e c9 [2] 22 ce [2] 3e e1 }

  condition:
    any of them
}