rule TTP_XOR_QUAD_CurrentVersionRun_38a4 {
  strings:
    $key_38a4 = { 6b cb [2] 4f c5 [2] 64 e9 [2] 4a cb [2] 5e d0 [2] 51 ca [2] 4f d7 [2] 4d d6 [2] 56 d0 [2] 4a d7 [2] 56 f8 }

  condition:
    any of them
}