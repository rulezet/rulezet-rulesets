rule TTP_XOR_QUAD_CurrentVersionRun_e9b8 {
  strings:
    $key_e9b8 = { ba d7 [2] 9e d9 [2] b5 f5 [2] 9b d7 [2] 8f cc [2] 80 d6 [2] 9e cb [2] 9c ca [2] 87 cc [2] 9b cb [2] 87 e4 }

  condition:
    any of them
}