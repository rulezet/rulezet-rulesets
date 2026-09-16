rule TTP_XOR_QUAD_CurrentVersionRun_bda6 {
  strings:
    $key_bda6 = { ee c9 [2] ca c7 [2] e1 eb [2] cf c9 [2] db d2 [2] d4 c8 [2] ca d5 [2] c8 d4 [2] d3 d2 [2] cf d5 [2] d3 fa }

  condition:
    any of them
}