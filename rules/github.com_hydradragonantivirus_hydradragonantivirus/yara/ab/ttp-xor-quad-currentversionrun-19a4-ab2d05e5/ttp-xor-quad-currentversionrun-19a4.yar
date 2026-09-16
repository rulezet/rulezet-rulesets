rule TTP_XOR_QUAD_CurrentVersionRun_19a4 {
  strings:
    $key_19a4 = { 4a cb [2] 6e c5 [2] 45 e9 [2] 6b cb [2] 7f d0 [2] 70 ca [2] 6e d7 [2] 6c d6 [2] 77 d0 [2] 6b d7 [2] 77 f8 }

  condition:
    any of them
}