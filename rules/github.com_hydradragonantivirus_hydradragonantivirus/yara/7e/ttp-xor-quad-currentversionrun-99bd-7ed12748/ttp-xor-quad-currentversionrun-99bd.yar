rule TTP_XOR_QUAD_CurrentVersionRun_99bd {
  strings:
    $key_99bd = { ca d2 [2] ee dc [2] c5 f0 [2] eb d2 [2] ff c9 [2] f0 d3 [2] ee ce [2] ec cf [2] f7 c9 [2] eb ce [2] f7 e1 }

  condition:
    any of them
}