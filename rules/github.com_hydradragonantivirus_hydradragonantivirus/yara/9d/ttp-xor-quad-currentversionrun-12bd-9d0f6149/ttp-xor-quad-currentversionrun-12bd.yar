rule TTP_XOR_QUAD_CurrentVersionRun_12bd {
  strings:
    $key_12bd = { 41 d2 [2] 65 dc [2] 4e f0 [2] 60 d2 [2] 74 c9 [2] 7b d3 [2] 65 ce [2] 67 cf [2] 7c c9 [2] 60 ce [2] 7c e1 }

  condition:
    any of them
}