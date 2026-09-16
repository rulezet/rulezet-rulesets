rule TTP_XOR_QUAD_CurrentVersionRun_c0bd {
  strings:
    $key_c0bd = { 93 d2 [2] b7 dc [2] 9c f0 [2] b2 d2 [2] a6 c9 [2] a9 d3 [2] b7 ce [2] b5 cf [2] ae c9 [2] b2 ce [2] ae e1 }

  condition:
    any of them
}