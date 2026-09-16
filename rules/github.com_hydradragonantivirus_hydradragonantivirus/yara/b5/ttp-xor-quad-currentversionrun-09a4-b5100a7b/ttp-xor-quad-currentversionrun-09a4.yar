rule TTP_XOR_QUAD_CurrentVersionRun_09a4 {
  strings:
    $key_09a4 = { 5a cb [2] 7e c5 [2] 55 e9 [2] 7b cb [2] 6f d0 [2] 60 ca [2] 7e d7 [2] 7c d6 [2] 67 d0 [2] 7b d7 [2] 67 f8 }

  condition:
    any of them
}