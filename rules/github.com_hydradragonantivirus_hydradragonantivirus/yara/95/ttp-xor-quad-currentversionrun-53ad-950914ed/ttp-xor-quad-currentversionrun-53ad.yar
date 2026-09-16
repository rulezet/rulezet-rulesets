rule TTP_XOR_QUAD_CurrentVersionRun_53ad {
  strings:
    $key_53ad = { 00 c2 [2] 24 cc [2] 0f e0 [2] 21 c2 [2] 35 d9 [2] 3a c3 [2] 24 de [2] 26 df [2] 3d d9 [2] 21 de [2] 3d f1 }

  condition:
    any of them
}