rule TTP_XOR_QUAD_CurrentVersionRun_e9a5 {
  strings:
    $key_e9a5 = { ba ca [2] 9e c4 [2] b5 e8 [2] 9b ca [2] 8f d1 [2] 80 cb [2] 9e d6 [2] 9c d7 [2] 87 d1 [2] 9b d6 [2] 87 f9 }

  condition:
    any of them
}