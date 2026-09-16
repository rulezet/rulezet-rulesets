rule TTP_XOR_QUAD_CurrentVersionRun_28a4 {
  strings:
    $key_28a4 = { 7b cb [2] 5f c5 [2] 74 e9 [2] 5a cb [2] 4e d0 [2] 41 ca [2] 5f d7 [2] 5d d6 [2] 46 d0 [2] 5a d7 [2] 46 f8 }

  condition:
    any of them
}