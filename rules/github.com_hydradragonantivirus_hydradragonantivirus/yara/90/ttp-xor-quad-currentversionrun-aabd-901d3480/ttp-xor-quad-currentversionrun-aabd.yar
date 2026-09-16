rule TTP_XOR_QUAD_CurrentVersionRun_aabd {
  strings:
    $key_aabd = { f9 d2 [2] dd dc [2] f6 f0 [2] d8 d2 [2] cc c9 [2] c3 d3 [2] dd ce [2] df cf [2] c4 c9 [2] d8 ce [2] c4 e1 }

  condition:
    any of them
}