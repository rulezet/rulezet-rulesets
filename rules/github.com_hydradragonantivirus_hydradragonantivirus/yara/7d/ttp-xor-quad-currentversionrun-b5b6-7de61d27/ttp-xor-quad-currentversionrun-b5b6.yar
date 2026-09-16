rule TTP_XOR_QUAD_CurrentVersionRun_b5b6 {
  strings:
    $key_b5b6 = { e6 d9 [2] c2 d7 [2] e9 fb [2] c7 d9 [2] d3 c2 [2] dc d8 [2] c2 c5 [2] c0 c4 [2] db c2 [2] c7 c5 [2] db ea }

  condition:
    any of them
}