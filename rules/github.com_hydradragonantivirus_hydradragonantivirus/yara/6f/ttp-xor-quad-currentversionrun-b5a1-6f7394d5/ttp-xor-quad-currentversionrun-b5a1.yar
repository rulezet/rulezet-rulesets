rule TTP_XOR_QUAD_CurrentVersionRun_b5a1 {
  strings:
    $key_b5a1 = { e6 ce [2] c2 c0 [2] e9 ec [2] c7 ce [2] d3 d5 [2] dc cf [2] c2 d2 [2] c0 d3 [2] db d5 [2] c7 d2 [2] db fd }

  condition:
    any of them
}