rule TTP_XOR_QUAD_CurrentVersionRun_c0a0 {
  strings:
    $key_c0a0 = { 93 cf [2] b7 c1 [2] 9c ed [2] b2 cf [2] a6 d4 [2] a9 ce [2] b7 d3 [2] b5 d2 [2] ae d4 [2] b2 d3 [2] ae fc }

  condition:
    any of them
}