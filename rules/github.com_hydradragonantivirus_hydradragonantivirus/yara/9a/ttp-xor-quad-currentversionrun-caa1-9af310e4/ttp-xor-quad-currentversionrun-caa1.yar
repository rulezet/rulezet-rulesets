rule TTP_XOR_QUAD_CurrentVersionRun_caa1 {
  strings:
    $key_caa1 = { 99 ce [2] bd c0 [2] 96 ec [2] b8 ce [2] ac d5 [2] a3 cf [2] bd d2 [2] bf d3 [2] a4 d5 [2] b8 d2 [2] a4 fd }

  condition:
    any of them
}