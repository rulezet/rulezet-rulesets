rule TTP_XOR_QUAD_CurrentVersionRun_30ad {
  strings:
    $key_30ad = { 63 c2 [2] 47 cc [2] 6c e0 [2] 42 c2 [2] 56 d9 [2] 59 c3 [2] 47 de [2] 45 df [2] 5e d9 [2] 42 de [2] 5e f1 }

  condition:
    any of them
}