rule TTP_XOR_QUAD_CurrentVersionRun_e9a4 {
  strings:
    $key_e9a4 = { ba cb [2] 9e c5 [2] b5 e9 [2] 9b cb [2] 8f d0 [2] 80 ca [2] 9e d7 [2] 9c d6 [2] 87 d0 [2] 9b d7 [2] 87 f8 }

  condition:
    any of them
}