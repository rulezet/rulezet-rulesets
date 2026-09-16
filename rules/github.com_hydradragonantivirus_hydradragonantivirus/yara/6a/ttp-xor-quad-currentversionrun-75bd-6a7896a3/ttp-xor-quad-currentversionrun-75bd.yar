rule TTP_XOR_QUAD_CurrentVersionRun_75bd {
  strings:
    $key_75bd = { 26 d2 [2] 02 dc [2] 29 f0 [2] 07 d2 [2] 13 c9 [2] 1c d3 [2] 02 ce [2] 00 cf [2] 1b c9 [2] 07 ce [2] 1b e1 }

  condition:
    any of them
}