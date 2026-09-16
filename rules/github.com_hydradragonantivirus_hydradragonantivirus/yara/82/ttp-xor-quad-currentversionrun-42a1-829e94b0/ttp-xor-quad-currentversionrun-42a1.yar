rule TTP_XOR_QUAD_CurrentVersionRun_42a1 {
  strings:
    $key_42a1 = { 11 ce [2] 35 c0 [2] 1e ec [2] 30 ce [2] 24 d5 [2] 2b cf [2] 35 d2 [2] 37 d3 [2] 2c d5 [2] 30 d2 [2] 2c fd }

  condition:
    any of them
}