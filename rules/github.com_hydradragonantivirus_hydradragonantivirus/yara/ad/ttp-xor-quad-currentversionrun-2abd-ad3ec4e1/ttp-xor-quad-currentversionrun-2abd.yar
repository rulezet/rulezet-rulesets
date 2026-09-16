rule TTP_XOR_QUAD_CurrentVersionRun_2abd {
  strings:
    $key_2abd = { 79 d2 [2] 5d dc [2] 76 f0 [2] 58 d2 [2] 4c c9 [2] 43 d3 [2] 5d ce [2] 5f cf [2] 44 c9 [2] 58 ce [2] 44 e1 }

  condition:
    any of them
}