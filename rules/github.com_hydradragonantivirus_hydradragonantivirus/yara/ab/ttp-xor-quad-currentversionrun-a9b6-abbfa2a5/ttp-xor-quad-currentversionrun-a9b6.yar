rule TTP_XOR_QUAD_CurrentVersionRun_a9b6 {
  strings:
    $key_a9b6 = { fa d9 [2] de d7 [2] f5 fb [2] db d9 [2] cf c2 [2] c0 d8 [2] de c5 [2] dc c4 [2] c7 c2 [2] db c5 [2] c7 ea }

  condition:
    any of them
}