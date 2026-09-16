rule TTP_XOR_QUAD_CurrentVersionRun_39a4 {
  strings:
    $key_39a4 = { 6a cb [2] 4e c5 [2] 65 e9 [2] 4b cb [2] 5f d0 [2] 50 ca [2] 4e d7 [2] 4c d6 [2] 57 d0 [2] 4b d7 [2] 57 f8 }

  condition:
    any of them
}