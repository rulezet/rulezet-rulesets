rule TTP_XOR_QUAD_CurrentVersionRun_afbd {
  strings:
    $key_afbd = { fc d2 [2] d8 dc [2] f3 f0 [2] dd d2 [2] c9 c9 [2] c6 d3 [2] d8 ce [2] da cf [2] c1 c9 [2] dd ce [2] c1 e1 }

  condition:
    any of them
}