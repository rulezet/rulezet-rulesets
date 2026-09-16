rule TTP_XOR_QUAD_CurrentVersionRun_c5bd {
  strings:
    $key_c5bd = { 96 d2 [2] b2 dc [2] 99 f0 [2] b7 d2 [2] a3 c9 [2] ac d3 [2] b2 ce [2] b0 cf [2] ab c9 [2] b7 ce [2] ab e1 }

  condition:
    any of them
}