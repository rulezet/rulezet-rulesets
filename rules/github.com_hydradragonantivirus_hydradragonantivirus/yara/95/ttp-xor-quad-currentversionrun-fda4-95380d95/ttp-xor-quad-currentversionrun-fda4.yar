rule TTP_XOR_QUAD_CurrentVersionRun_fda4 {
  strings:
    $key_fda4 = { ae cb [2] 8a c5 [2] a1 e9 [2] 8f cb [2] 9b d0 [2] 94 ca [2] 8a d7 [2] 88 d6 [2] 93 d0 [2] 8f d7 [2] 93 f8 }

  condition:
    any of them
}