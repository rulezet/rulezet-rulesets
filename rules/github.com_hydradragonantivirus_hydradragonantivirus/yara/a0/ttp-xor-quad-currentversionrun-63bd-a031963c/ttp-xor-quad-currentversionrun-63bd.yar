rule TTP_XOR_QUAD_CurrentVersionRun_63bd {
  strings:
    $key_63bd = { 30 d2 [2] 14 dc [2] 3f f0 [2] 11 d2 [2] 05 c9 [2] 0a d3 [2] 14 ce [2] 16 cf [2] 0d c9 [2] 11 ce [2] 0d e1 }

  condition:
    any of them
}