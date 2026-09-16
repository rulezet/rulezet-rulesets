rule TTP_XOR_QUAD_CurrentVersionRun_b5a0 {
  strings:
    $key_b5a0 = { e6 cf [2] c2 c1 [2] e9 ed [2] c7 cf [2] d3 d4 [2] dc ce [2] c2 d3 [2] c0 d2 [2] db d4 [2] c7 d3 [2] db fc }

  condition:
    any of them
}