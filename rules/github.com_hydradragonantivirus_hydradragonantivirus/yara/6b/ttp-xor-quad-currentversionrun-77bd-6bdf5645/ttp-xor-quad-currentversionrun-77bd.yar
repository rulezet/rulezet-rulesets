rule TTP_XOR_QUAD_CurrentVersionRun_77bd {
  strings:
    $key_77bd = { 24 d2 [2] 00 dc [2] 2b f0 [2] 05 d2 [2] 11 c9 [2] 1e d3 [2] 00 ce [2] 02 cf [2] 19 c9 [2] 05 ce [2] 19 e1 }

  condition:
    any of them
}