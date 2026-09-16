rule TTP_XOR_QUAD_CurrentVersionRun_e3bd {
  strings:
    $key_e3bd = { b0 d2 [2] 94 dc [2] bf f0 [2] 91 d2 [2] 85 c9 [2] 8a d3 [2] 94 ce [2] 96 cf [2] 8d c9 [2] 91 ce [2] 8d e1 }

  condition:
    any of them
}