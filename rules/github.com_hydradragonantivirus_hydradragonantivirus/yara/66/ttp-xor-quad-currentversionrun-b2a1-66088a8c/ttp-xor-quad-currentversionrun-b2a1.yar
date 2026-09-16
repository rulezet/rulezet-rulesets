rule TTP_XOR_QUAD_CurrentVersionRun_b2a1 {
  strings:
    $key_b2a1 = { e1 ce [2] c5 c0 [2] ee ec [2] c0 ce [2] d4 d5 [2] db cf [2] c5 d2 [2] c7 d3 [2] dc d5 [2] c0 d2 [2] dc fd }

  condition:
    any of them
}