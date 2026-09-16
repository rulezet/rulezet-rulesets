rule TTP_XOR_QUAD_CurrentVersionRun_aeb7 {
  strings:
    $key_aeb7 = { fd d8 [2] d9 d6 [2] f2 fa [2] dc d8 [2] c8 c3 [2] c7 d9 [2] d9 c4 [2] db c5 [2] c0 c3 [2] dc c4 [2] c0 eb }

  condition:
    any of them
}