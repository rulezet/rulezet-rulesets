rule TTP_XOR_QUAD_CurrentVersionRun_f2bd {
  strings:
    $key_f2bd = { a1 d2 [2] 85 dc [2] ae f0 [2] 80 d2 [2] 94 c9 [2] 9b d3 [2] 85 ce [2] 87 cf [2] 9c c9 [2] 80 ce [2] 9c e1 }

  condition:
    any of them
}