rule TTP_XOR_QUAD_CurrentVersionRun_04ad {
  strings:
    $key_04ad = { 57 c2 [2] 73 cc [2] 58 e0 [2] 76 c2 [2] 62 d9 [2] 6d c3 [2] 73 de [2] 71 df [2] 6a d9 [2] 76 de [2] 6a f1 }

  condition:
    any of them
}