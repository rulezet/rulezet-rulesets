rule TTP_XOR_QUAD_CurrentVersionRun_e8a4 {
  strings:
    $key_e8a4 = { bb cb [2] 9f c5 [2] b4 e9 [2] 9a cb [2] 8e d0 [2] 81 ca [2] 9f d7 [2] 9d d6 [2] 86 d0 [2] 9a d7 [2] 86 f8 }

  condition:
    any of them
}