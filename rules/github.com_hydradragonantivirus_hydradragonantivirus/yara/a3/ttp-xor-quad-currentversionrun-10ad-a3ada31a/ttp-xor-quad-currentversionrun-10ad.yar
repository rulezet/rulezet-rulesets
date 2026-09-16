rule TTP_XOR_QUAD_CurrentVersionRun_10ad {
  strings:
    $key_10ad = { 43 c2 [2] 67 cc [2] 4c e0 [2] 62 c2 [2] 76 d9 [2] 79 c3 [2] 67 de [2] 65 df [2] 7e d9 [2] 62 de [2] 7e f1 }

  condition:
    any of them
}