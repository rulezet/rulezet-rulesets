rule TTP_XOR_QUAD_CurrentVersionRun_3ca1 {
  strings:
    $key_3ca1 = { 6f ce [2] 4b c0 [2] 60 ec [2] 4e ce [2] 5a d5 [2] 55 cf [2] 4b d2 [2] 49 d3 [2] 52 d5 [2] 4e d2 [2] 52 fd }

  condition:
    any of them
}