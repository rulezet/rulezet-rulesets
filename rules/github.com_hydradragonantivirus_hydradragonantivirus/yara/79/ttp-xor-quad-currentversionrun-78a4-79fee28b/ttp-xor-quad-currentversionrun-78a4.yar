rule TTP_XOR_QUAD_CurrentVersionRun_78a4 {
  strings:
    $key_78a4 = { 2b cb [2] 0f c5 [2] 24 e9 [2] 0a cb [2] 1e d0 [2] 11 ca [2] 0f d7 [2] 0d d6 [2] 16 d0 [2] 0a d7 [2] 16 f8 }

  condition:
    any of them
}