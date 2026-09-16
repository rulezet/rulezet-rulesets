rule TTP_XOR_QUAD_CurrentVersionRun_7ca1 {
  strings:
    $key_7ca1 = { 2f ce [2] 0b c0 [2] 20 ec [2] 0e ce [2] 1a d5 [2] 15 cf [2] 0b d2 [2] 09 d3 [2] 12 d5 [2] 0e d2 [2] 12 fd }

  condition:
    any of them
}