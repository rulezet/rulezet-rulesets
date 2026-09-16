rule TTP_XOR_QUAD_CurrentVersionRun_22bd {
  strings:
    $key_22bd = { 71 d2 [2] 55 dc [2] 7e f0 [2] 50 d2 [2] 44 c9 [2] 4b d3 [2] 55 ce [2] 57 cf [2] 4c c9 [2] 50 ce [2] 4c e1 }

  condition:
    any of them
}