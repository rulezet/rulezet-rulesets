rule TTP_XOR_QUAD_CurrentVersionRun_b6a1 {
  strings:
    $key_b6a1 = { e5 ce [2] c1 c0 [2] ea ec [2] c4 ce [2] d0 d5 [2] df cf [2] c1 d2 [2] c3 d3 [2] d8 d5 [2] c4 d2 [2] d8 fd }

  condition:
    any of them
}