rule TTP_XOR_QUAD_CurrentVersionRun_13ad {
  strings:
    $key_13ad = { 40 c2 [2] 64 cc [2] 4f e0 [2] 61 c2 [2] 75 d9 [2] 7a c3 [2] 64 de [2] 66 df [2] 7d d9 [2] 61 de [2] 7d f1 }

  condition:
    any of them
}