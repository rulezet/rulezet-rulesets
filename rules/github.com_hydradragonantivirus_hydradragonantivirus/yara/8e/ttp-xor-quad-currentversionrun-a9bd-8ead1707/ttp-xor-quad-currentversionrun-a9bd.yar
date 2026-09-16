rule TTP_XOR_QUAD_CurrentVersionRun_a9bd {
  strings:
    $key_a9bd = { fa d2 [2] de dc [2] f5 f0 [2] db d2 [2] cf c9 [2] c0 d3 [2] de ce [2] dc cf [2] c7 c9 [2] db ce [2] c7 e1 }

  condition:
    any of them
}