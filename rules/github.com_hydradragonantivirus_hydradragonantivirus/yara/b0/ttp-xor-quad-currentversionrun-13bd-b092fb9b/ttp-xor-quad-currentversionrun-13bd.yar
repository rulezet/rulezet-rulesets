rule TTP_XOR_QUAD_CurrentVersionRun_13bd {
  strings:
    $key_13bd = { 40 d2 [2] 64 dc [2] 4f f0 [2] 61 d2 [2] 75 c9 [2] 7a d3 [2] 64 ce [2] 66 cf [2] 7d c9 [2] 61 ce [2] 7d e1 }

  condition:
    any of them
}