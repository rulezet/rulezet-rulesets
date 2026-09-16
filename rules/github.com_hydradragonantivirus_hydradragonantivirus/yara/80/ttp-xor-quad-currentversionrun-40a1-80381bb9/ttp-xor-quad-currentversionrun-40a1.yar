rule TTP_XOR_QUAD_CurrentVersionRun_40a1 {
  strings:
    $key_40a1 = { 13 ce [2] 37 c0 [2] 1c ec [2] 32 ce [2] 26 d5 [2] 29 cf [2] 37 d2 [2] 35 d3 [2] 2e d5 [2] 32 d2 [2] 2e fd }

  condition:
    any of them
}