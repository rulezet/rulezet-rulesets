rule TTP_XOR_QUAD_CurrentVersionRun_f8a4 {
  strings:
    $key_f8a4 = { ab cb [2] 8f c5 [2] a4 e9 [2] 8a cb [2] 9e d0 [2] 91 ca [2] 8f d7 [2] 8d d6 [2] 96 d0 [2] 8a d7 [2] 96 f8 }

  condition:
    any of them
}