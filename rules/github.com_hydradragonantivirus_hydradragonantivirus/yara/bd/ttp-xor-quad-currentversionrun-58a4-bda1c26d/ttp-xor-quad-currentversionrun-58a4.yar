rule TTP_XOR_QUAD_CurrentVersionRun_58a4 {
  strings:
    $key_58a4 = { 0b cb [2] 2f c5 [2] 04 e9 [2] 2a cb [2] 3e d0 [2] 31 ca [2] 2f d7 [2] 2d d6 [2] 36 d0 [2] 2a d7 [2] 36 f8 }

  condition:
    any of them
}