rule TTP_XOR_QUAD_CurrentVersionRun_67bd {
  strings:
    $key_67bd = { 34 d2 [2] 10 dc [2] 3b f0 [2] 15 d2 [2] 01 c9 [2] 0e d3 [2] 10 ce [2] 12 cf [2] 09 c9 [2] 15 ce [2] 09 e1 }

  condition:
    any of them
}