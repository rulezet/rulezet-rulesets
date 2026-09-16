rule TTP_XOR_QUAD_CurrentVersionRun_debd {
  strings:
    $key_debd = { 8d d2 [2] a9 dc [2] 82 f0 [2] ac d2 [2] b8 c9 [2] b7 d3 [2] a9 ce [2] ab cf [2] b0 c9 [2] ac ce [2] b0 e1 }

  condition:
    any of them
}