rule TTP_XOR_QUAD_CurrentVersionRun_0ca1 {
  strings:
    $key_0ca1 = { 5f ce [2] 7b c0 [2] 50 ec [2] 7e ce [2] 6a d5 [2] 65 cf [2] 7b d2 [2] 79 d3 [2] 62 d5 [2] 7e d2 [2] 62 fd }

  condition:
    any of them
}