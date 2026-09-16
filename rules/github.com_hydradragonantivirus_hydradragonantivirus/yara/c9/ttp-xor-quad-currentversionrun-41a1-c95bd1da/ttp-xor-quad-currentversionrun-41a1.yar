rule TTP_XOR_QUAD_CurrentVersionRun_41a1 {
  strings:
    $key_41a1 = { 12 ce [2] 36 c0 [2] 1d ec [2] 33 ce [2] 27 d5 [2] 28 cf [2] 36 d2 [2] 34 d3 [2] 2f d5 [2] 33 d2 [2] 2f fd }

  condition:
    any of them
}