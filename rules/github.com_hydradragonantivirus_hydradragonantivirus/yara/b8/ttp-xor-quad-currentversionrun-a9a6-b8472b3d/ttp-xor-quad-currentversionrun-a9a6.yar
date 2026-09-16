rule TTP_XOR_QUAD_CurrentVersionRun_a9a6 {
  strings:
    $key_a9a6 = { fa c9 [2] de c7 [2] f5 eb [2] db c9 [2] cf d2 [2] c0 c8 [2] de d5 [2] dc d4 [2] c7 d2 [2] db d5 [2] c7 fa }

  condition:
    any of them
}