rule TTP_XOR_QUAD_CurrentVersionRun_dba0 {
  strings:
    $key_dba0 = { 88 cf [2] ac c1 [2] 87 ed [2] a9 cf [2] bd d4 [2] b2 ce [2] ac d3 [2] ae d2 [2] b5 d4 [2] a9 d3 [2] b5 fc }

  condition:
    any of them
}