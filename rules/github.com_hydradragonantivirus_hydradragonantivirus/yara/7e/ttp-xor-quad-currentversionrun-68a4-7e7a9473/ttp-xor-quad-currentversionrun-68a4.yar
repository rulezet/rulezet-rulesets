rule TTP_XOR_QUAD_CurrentVersionRun_68a4 {
  strings:
    $key_68a4 = { 3b cb [2] 1f c5 [2] 34 e9 [2] 1a cb [2] 0e d0 [2] 01 ca [2] 1f d7 [2] 1d d6 [2] 06 d0 [2] 1a d7 [2] 06 f8 }

  condition:
    any of them
}