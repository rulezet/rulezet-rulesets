rule TTP_XOR_QUAD_CurrentVersionRun_fdaa {
  strings:
    $key_fdaa = { ae c5 [2] 8a cb [2] a1 e7 [2] 8f c5 [2] 9b de [2] 94 c4 [2] 8a d9 [2] 88 d8 [2] 93 de [2] 8f d9 [2] 93 f6 }

  condition:
    any of them
}