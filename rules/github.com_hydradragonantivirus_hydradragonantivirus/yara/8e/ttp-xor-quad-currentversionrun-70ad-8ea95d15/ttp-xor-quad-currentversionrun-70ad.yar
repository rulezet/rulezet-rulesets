rule TTP_XOR_QUAD_CurrentVersionRun_70ad {
  strings:
    $key_70ad = { 23 c2 [2] 07 cc [2] 2c e0 [2] 02 c2 [2] 16 d9 [2] 19 c3 [2] 07 de [2] 05 df [2] 1e d9 [2] 02 de [2] 1e f1 }

  condition:
    any of them
}