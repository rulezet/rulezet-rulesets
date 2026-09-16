rule TTP_XOR_QUAD_CurrentVersionRun_21ad {
  strings:
    $key_21ad = { 72 c2 [2] 56 cc [2] 7d e0 [2] 53 c2 [2] 47 d9 [2] 48 c3 [2] 56 de [2] 54 df [2] 4f d9 [2] 53 de [2] 4f f1 }

  condition:
    any of them
}