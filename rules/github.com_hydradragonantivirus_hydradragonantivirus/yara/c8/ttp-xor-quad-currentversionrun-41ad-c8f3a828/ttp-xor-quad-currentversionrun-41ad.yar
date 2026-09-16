rule TTP_XOR_QUAD_CurrentVersionRun_41ad {
  strings:
    $key_41ad = { 12 c2 [2] 36 cc [2] 1d e0 [2] 33 c2 [2] 27 d9 [2] 28 c3 [2] 36 de [2] 34 df [2] 2f d9 [2] 33 de [2] 2f f1 }

  condition:
    any of them
}