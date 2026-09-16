rule TTP_XOR_QUAD_CurrentVersionRun_25bd {
  strings:
    $key_25bd = { 76 d2 [2] 52 dc [2] 79 f0 [2] 57 d2 [2] 43 c9 [2] 4c d3 [2] 52 ce [2] 50 cf [2] 4b c9 [2] 57 ce [2] 4b e1 }

  condition:
    any of them
}