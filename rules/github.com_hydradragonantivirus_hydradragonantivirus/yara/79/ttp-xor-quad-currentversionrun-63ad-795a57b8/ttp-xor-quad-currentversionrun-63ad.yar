rule TTP_XOR_QUAD_CurrentVersionRun_63ad {
  strings:
    $key_63ad = { 30 c2 [2] 14 cc [2] 3f e0 [2] 11 c2 [2] 05 d9 [2] 0a c3 [2] 14 de [2] 16 df [2] 0d d9 [2] 11 de [2] 0d f1 }

  condition:
    any of them
}