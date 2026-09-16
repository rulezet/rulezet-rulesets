rule TTP_XOR_QUAD_CurrentVersionRun_52a1 {
  strings:
    $key_52a1 = { 01 ce [2] 25 c0 [2] 0e ec [2] 20 ce [2] 34 d5 [2] 3b cf [2] 25 d2 [2] 27 d3 [2] 3c d5 [2] 20 d2 [2] 3c fd }

  condition:
    any of them
}