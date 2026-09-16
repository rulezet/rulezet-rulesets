rule TTP_XOR_QUAD_CurrentVersionRun_b2a0 {
  strings:
    $key_b2a0 = { e1 cf [2] c5 c1 [2] ee ed [2] c0 cf [2] d4 d4 [2] db ce [2] c5 d3 [2] c7 d2 [2] dc d4 [2] c0 d3 [2] dc fc }

  condition:
    any of them
}