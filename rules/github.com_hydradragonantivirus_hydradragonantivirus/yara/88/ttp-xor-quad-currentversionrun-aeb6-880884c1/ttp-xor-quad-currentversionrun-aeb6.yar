rule TTP_XOR_QUAD_CurrentVersionRun_aeb6 {
  strings:
    $key_aeb6 = { fd d9 [2] d9 d7 [2] f2 fb [2] dc d9 [2] c8 c2 [2] c7 d8 [2] d9 c5 [2] db c4 [2] c0 c2 [2] dc c5 [2] c0 ea }

  condition:
    any of them
}