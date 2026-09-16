rule TTP_XOR_QUAD_CurrentVersionRun_08a4 {
  strings:
    $key_08a4 = { 5b cb [2] 7f c5 [2] 54 e9 [2] 7a cb [2] 6e d0 [2] 61 ca [2] 7f d7 [2] 7d d6 [2] 66 d0 [2] 7a d7 [2] 66 f8 }

  condition:
    any of them
}