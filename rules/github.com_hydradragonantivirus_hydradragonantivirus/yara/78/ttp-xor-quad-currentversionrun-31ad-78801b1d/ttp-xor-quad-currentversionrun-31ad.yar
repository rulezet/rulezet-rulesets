rule TTP_XOR_QUAD_CurrentVersionRun_31ad {
  strings:
    $key_31ad = { 62 c2 [2] 46 cc [2] 6d e0 [2] 43 c2 [2] 57 d9 [2] 58 c3 [2] 46 de [2] 44 df [2] 5f d9 [2] 43 de [2] 5f f1 }

  condition:
    any of them
}