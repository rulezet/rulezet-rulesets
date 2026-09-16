rule TTP_XOR_QUAD_CurrentVersionRun_74bd {
  strings:
    $key_74bd = { 27 d2 [2] 03 dc [2] 28 f0 [2] 06 d2 [2] 12 c9 [2] 1d d3 [2] 03 ce [2] 01 cf [2] 1a c9 [2] 06 ce [2] 1a e1 }

  condition:
    any of them
}