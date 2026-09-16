rule TTP_XOR_QUAD_CurrentVersionRun_bbbd {
  strings:
    $key_bbbd = { e8 d2 [2] cc dc [2] e7 f0 [2] c9 d2 [2] dd c9 [2] d2 d3 [2] cc ce [2] ce cf [2] d5 c9 [2] c9 ce [2] d5 e1 }

  condition:
    any of them
}