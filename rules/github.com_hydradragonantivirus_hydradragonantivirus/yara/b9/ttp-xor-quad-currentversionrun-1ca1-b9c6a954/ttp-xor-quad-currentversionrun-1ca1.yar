rule TTP_XOR_QUAD_CurrentVersionRun_1ca1 {
  strings:
    $key_1ca1 = { 4f ce [2] 6b c0 [2] 40 ec [2] 6e ce [2] 7a d5 [2] 75 cf [2] 6b d2 [2] 69 d3 [2] 72 d5 [2] 6e d2 [2] 72 fd }

  condition:
    any of them
}