rule TTP_XOR_QUAD_CurrentVersionRun_55bd {
  strings:
    $key_55bd = { 06 d2 [2] 22 dc [2] 09 f0 [2] 27 d2 [2] 33 c9 [2] 3c d3 [2] 22 ce [2] 20 cf [2] 3b c9 [2] 27 ce [2] 3b e1 }

  condition:
    any of them
}