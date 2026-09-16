rule TTP_XOR_QUAD_CurrentVersionRun_64ad {
  strings:
    $key_64ad = { 37 c2 [2] 13 cc [2] 38 e0 [2] 16 c2 [2] 02 d9 [2] 0d c3 [2] 13 de [2] 11 df [2] 0a d9 [2] 16 de [2] 0a f1 }

  condition:
    any of them
}