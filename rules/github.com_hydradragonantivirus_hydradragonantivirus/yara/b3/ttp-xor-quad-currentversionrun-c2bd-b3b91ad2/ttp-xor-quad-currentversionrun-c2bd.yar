rule TTP_XOR_QUAD_CurrentVersionRun_c2bd {
  strings:
    $key_c2bd = { 91 d2 [2] b5 dc [2] 9e f0 [2] b0 d2 [2] a4 c9 [2] ab d3 [2] b5 ce [2] b7 cf [2] ac c9 [2] b0 ce [2] ac e1 }

  condition:
    any of them
}