rule TTP_XOR_QUAD_CurrentVersionRun_c5a0 {
  strings:
    $key_c5a0 = { 96 cf [2] b2 c1 [2] 99 ed [2] b7 cf [2] a3 d4 [2] ac ce [2] b2 d3 [2] b0 d2 [2] ab d4 [2] b7 d3 [2] ab fc }

  condition:
    any of them
}