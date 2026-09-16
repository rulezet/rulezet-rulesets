rule TTP_XOR_QUAD_CurrentVersionRun_e7bd {
  strings:
    $key_e7bd = { b4 d2 [2] 90 dc [2] bb f0 [2] 95 d2 [2] 81 c9 [2] 8e d3 [2] 90 ce [2] 92 cf [2] 89 c9 [2] 95 ce [2] 89 e1 }

  condition:
    any of them
}