rule TTP_XOR_QUAD_CurrentVersionRun_a7ad {
  strings:
    $key_a7ad = { f4 c2 [2] d0 cc [2] fb e0 [2] d5 c2 [2] c1 d9 [2] ce c3 [2] d0 de [2] d2 df [2] c9 d9 [2] d5 de [2] c9 f1 }

  condition:
    any of them
}