rule TTP_XOR_QUAD_CurrentVersionRun_a9a7 {
  strings:
    $key_a9a7 = { fa c8 [2] de c6 [2] f5 ea [2] db c8 [2] cf d3 [2] c0 c9 [2] de d4 [2] dc d5 [2] c7 d3 [2] db d4 [2] c7 fb }

  condition:
    any of them
}