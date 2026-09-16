rule TTP_XOR_QUAD_CurrentVersionRun_e6ad {
  strings:
    $key_e6ad = { b5 c2 [2] 91 cc [2] ba e0 [2] 94 c2 [2] 80 d9 [2] 8f c3 [2] 91 de [2] 93 df [2] 88 d9 [2] 94 de [2] 88 f1 }

  condition:
    any of them
}