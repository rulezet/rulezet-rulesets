rule TTP_XOR_QUAD_CurrentVersionRun_74ad {
  strings:
    $key_74ad = { 27 c2 [2] 03 cc [2] 28 e0 [2] 06 c2 [2] 12 d9 [2] 1d c3 [2] 03 de [2] 01 df [2] 1a d9 [2] 06 de [2] 1a f1 }

  condition:
    any of them
}