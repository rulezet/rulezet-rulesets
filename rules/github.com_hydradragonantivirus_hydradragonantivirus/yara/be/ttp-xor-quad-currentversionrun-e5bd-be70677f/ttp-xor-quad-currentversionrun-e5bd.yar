rule TTP_XOR_QUAD_CurrentVersionRun_e5bd {
  strings:
    $key_e5bd = { b6 d2 [2] 92 dc [2] b9 f0 [2] 97 d2 [2] 83 c9 [2] 8c d3 [2] 92 ce [2] 90 cf [2] 8b c9 [2] 97 ce [2] 8b e1 }

  condition:
    any of them
}