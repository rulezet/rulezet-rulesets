rule TTP_XOR_QUAD_CurrentVersionRun_b1ad {
  strings:
    $key_b1ad = { e2 c2 [2] c6 cc [2] ed e0 [2] c3 c2 [2] d7 d9 [2] d8 c3 [2] c6 de [2] c4 df [2] df d9 [2] c3 de [2] df f1 }

  condition:
    any of them
}