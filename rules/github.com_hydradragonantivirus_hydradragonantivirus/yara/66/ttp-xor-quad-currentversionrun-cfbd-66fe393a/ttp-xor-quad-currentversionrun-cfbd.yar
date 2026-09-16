rule TTP_XOR_QUAD_CurrentVersionRun_cfbd {
  strings:
    $key_cfbd = { 9c d2 [2] b8 dc [2] 93 f0 [2] bd d2 [2] a9 c9 [2] a6 d3 [2] b8 ce [2] ba cf [2] a1 c9 [2] bd ce [2] a1 e1 }

  condition:
    any of them
}