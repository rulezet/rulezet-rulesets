rule TTP_XOR_QUAD_CurrentVersionRun_f1a1 {
  strings:
    $key_f1a1 = { a2 ce [2] 86 c0 [2] ad ec [2] 83 ce [2] 97 d5 [2] 98 cf [2] 86 d2 [2] 84 d3 [2] 9f d5 [2] 83 d2 [2] 9f fd }

  condition:
    any of them
}