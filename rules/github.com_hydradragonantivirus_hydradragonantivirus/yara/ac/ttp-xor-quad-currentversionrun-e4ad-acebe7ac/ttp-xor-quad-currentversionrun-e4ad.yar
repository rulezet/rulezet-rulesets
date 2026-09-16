rule TTP_XOR_QUAD_CurrentVersionRun_e4ad {
  strings:
    $key_e4ad = { b7 c2 [2] 93 cc [2] b8 e0 [2] 96 c2 [2] 82 d9 [2] 8d c3 [2] 93 de [2] 91 df [2] 8a d9 [2] 96 de [2] 8a f1 }

  condition:
    any of them
}