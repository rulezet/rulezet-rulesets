rule TTP_XOR_QUAD_CurrentVersionRun_10a1 {
  strings:
    $key_10a1 = { 43 ce [2] 67 c0 [2] 4c ec [2] 62 ce [2] 76 d5 [2] 79 cf [2] 67 d2 [2] 65 d3 [2] 7e d5 [2] 62 d2 [2] 7e fd }

  condition:
    any of them
}