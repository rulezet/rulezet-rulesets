rule TTP_XOR_QUAD_CurrentVersionRun_a9bc {
  strings:
    $key_a9bc = { fa d3 [2] de dd [2] f5 f1 [2] db d3 [2] cf c8 [2] c0 d2 [2] de cf [2] dc ce [2] c7 c8 [2] db cf [2] c7 e0 }

  condition:
    any of them
}