rule TTP_XOR_QUAD_CurrentVersionRun_5abd {
  strings:
    $key_5abd = { 09 d2 [2] 2d dc [2] 06 f0 [2] 28 d2 [2] 3c c9 [2] 33 d3 [2] 2d ce [2] 2f cf [2] 34 c9 [2] 28 ce [2] 34 e1 }

  condition:
    any of them
}