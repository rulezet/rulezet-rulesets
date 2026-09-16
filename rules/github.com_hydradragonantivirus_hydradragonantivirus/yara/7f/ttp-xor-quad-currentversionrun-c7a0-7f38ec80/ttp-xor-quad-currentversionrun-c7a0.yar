rule TTP_XOR_QUAD_CurrentVersionRun_c7a0 {
  strings:
    $key_c7a0 = { 94 cf [2] b0 c1 [2] 9b ed [2] b5 cf [2] a1 d4 [2] ae ce [2] b0 d3 [2] b2 d2 [2] a9 d4 [2] b5 d3 [2] a9 fc }

  condition:
    any of them
}