rule TTP_XOR_QUAD_CurrentVersionRun_b7ad {
  strings:
    $key_b7ad = { e4 c2 [2] c0 cc [2] eb e0 [2] c5 c2 [2] d1 d9 [2] de c3 [2] c0 de [2] c2 df [2] d9 d9 [2] c5 de [2] d9 f1 }

  condition:
    any of them
}