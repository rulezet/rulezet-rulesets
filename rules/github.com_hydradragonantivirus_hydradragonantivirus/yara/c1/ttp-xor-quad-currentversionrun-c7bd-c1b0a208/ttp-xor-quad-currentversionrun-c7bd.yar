rule TTP_XOR_QUAD_CurrentVersionRun_c7bd {
  strings:
    $key_c7bd = { 94 d2 [2] b0 dc [2] 9b f0 [2] b5 d2 [2] a1 c9 [2] ae d3 [2] b0 ce [2] b2 cf [2] a9 c9 [2] b5 ce [2] a9 e1 }

  condition:
    any of them
}