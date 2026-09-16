rule TTP_XOR_QUAD_CurrentVersionRun_aea1 {
  strings:
    $key_aea1 = { fd ce [2] d9 c0 [2] f2 ec [2] dc ce [2] c8 d5 [2] c7 cf [2] d9 d2 [2] db d3 [2] c0 d5 [2] dc d2 [2] c0 fd }

  condition:
    any of them
}