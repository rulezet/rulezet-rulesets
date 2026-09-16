rule TTP_XOR_QUAD_CurrentVersionRun_40ad {
  strings:
    $key_40ad = { 13 c2 [2] 37 cc [2] 1c e0 [2] 32 c2 [2] 26 d9 [2] 29 c3 [2] 37 de [2] 35 df [2] 2e d9 [2] 32 de [2] 2e f1 }

  condition:
    any of them
}