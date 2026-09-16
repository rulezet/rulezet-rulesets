rule TTP_XOR_QUAD_CurrentVersionRun_02bd {
  strings:
    $key_02bd = { 51 d2 [2] 75 dc [2] 5e f0 [2] 70 d2 [2] 64 c9 [2] 6b d3 [2] 75 ce [2] 77 cf [2] 6c c9 [2] 70 ce [2] 6c e1 }

  condition:
    any of them
}