rule TTP_XOR_QUAD_CurrentVersionRun_e3ad {
  strings:
    $key_e3ad = { b0 c2 [2] 94 cc [2] bf e0 [2] 91 c2 [2] 85 d9 [2] 8a c3 [2] 94 de [2] 96 df [2] 8d d9 [2] 91 de [2] 8d f1 }

  condition:
    any of them
}