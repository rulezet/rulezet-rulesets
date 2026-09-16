rule TTP_XOR_QUAD_CurrentVersionRun_daa1 {
  strings:
    $key_daa1 = { 89 ce [2] ad c0 [2] 86 ec [2] a8 ce [2] bc d5 [2] b3 cf [2] ad d2 [2] af d3 [2] b4 d5 [2] a8 d2 [2] b4 fd }

  condition:
    any of them
}