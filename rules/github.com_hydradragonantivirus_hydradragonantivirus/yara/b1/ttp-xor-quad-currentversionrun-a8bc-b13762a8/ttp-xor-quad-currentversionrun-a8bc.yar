rule TTP_XOR_QUAD_CurrentVersionRun_a8bc {
  strings:
    $key_a8bc = { fb d3 [2] df dd [2] f4 f1 [2] da d3 [2] ce c8 [2] c1 d2 [2] df cf [2] dd ce [2] c6 c8 [2] da cf [2] c6 e0 }

  condition:
    any of them
}