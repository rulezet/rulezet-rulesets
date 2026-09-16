rule TTP_XOR_QUAD_CurrentVersionRun_f6bd {
  strings:
    $key_f6bd = { a5 d2 [2] 81 dc [2] aa f0 [2] 84 d2 [2] 90 c9 [2] 9f d3 [2] 81 ce [2] 83 cf [2] 98 c9 [2] 84 ce [2] 98 e1 }

  condition:
    any of them
}