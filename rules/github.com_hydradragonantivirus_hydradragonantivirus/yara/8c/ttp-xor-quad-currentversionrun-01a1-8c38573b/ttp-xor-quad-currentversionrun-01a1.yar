rule TTP_XOR_QUAD_CurrentVersionRun_01a1 {
  strings:
    $key_01a1 = { 52 ce [2] 76 c0 [2] 5d ec [2] 73 ce [2] 67 d5 [2] 68 cf [2] 76 d2 [2] 74 d3 [2] 6f d5 [2] 73 d2 [2] 6f fd }

  condition:
    any of them
}