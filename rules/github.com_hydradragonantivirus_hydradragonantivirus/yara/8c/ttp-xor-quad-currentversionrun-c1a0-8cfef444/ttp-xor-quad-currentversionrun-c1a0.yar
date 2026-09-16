rule TTP_XOR_QUAD_CurrentVersionRun_c1a0 {
  strings:
    $key_c1a0 = { 92 cf [2] b6 c1 [2] 9d ed [2] b3 cf [2] a7 d4 [2] a8 ce [2] b6 d3 [2] b4 d2 [2] af d4 [2] b3 d3 [2] af fc }

  condition:
    any of them
}