rule TTP_XOR_QUAD_CurrentVersionRun_73ad {
  strings:
    $key_73ad = { 20 c2 [2] 04 cc [2] 2f e0 [2] 01 c2 [2] 15 d9 [2] 1a c3 [2] 04 de [2] 06 df [2] 1d d9 [2] 01 de [2] 1d f1 }

  condition:
    any of them
}