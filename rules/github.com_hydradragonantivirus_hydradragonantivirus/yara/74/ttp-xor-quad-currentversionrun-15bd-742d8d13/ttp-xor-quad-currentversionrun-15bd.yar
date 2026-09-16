rule TTP_XOR_QUAD_CurrentVersionRun_15bd {
  strings:
    $key_15bd = { 46 d2 [2] 62 dc [2] 49 f0 [2] 67 d2 [2] 73 c9 [2] 7c d3 [2] 62 ce [2] 60 cf [2] 7b c9 [2] 67 ce [2] 7b e1 }

  condition:
    any of them
}