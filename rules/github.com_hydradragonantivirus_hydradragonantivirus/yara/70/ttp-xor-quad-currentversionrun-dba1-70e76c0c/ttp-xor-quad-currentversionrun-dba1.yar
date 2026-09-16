rule TTP_XOR_QUAD_CurrentVersionRun_dba1 {
  strings:
    $key_dba1 = { 88 ce [2] ac c0 [2] 87 ec [2] a9 ce [2] bd d5 [2] b2 cf [2] ac d2 [2] ae d3 [2] b5 d5 [2] a9 d2 [2] b5 fd }

  condition:
    any of them
}