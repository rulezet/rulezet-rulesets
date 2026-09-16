rule TTP_XOR_QUAD_CurrentVersionRun_51a1 {
  strings:
    $key_51a1 = { 02 ce [2] 26 c0 [2] 0d ec [2] 23 ce [2] 37 d5 [2] 38 cf [2] 26 d2 [2] 24 d3 [2] 3f d5 [2] 23 d2 [2] 3f fd }

  condition:
    any of them
}