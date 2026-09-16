rule TTP_XOR_QUAD_CurrentVersionRun_ecb7 {
  strings:
    $key_ecb7 = { bf d8 [2] 9b d6 [2] b0 fa [2] 9e d8 [2] 8a c3 [2] 85 d9 [2] 9b c4 [2] 99 c5 [2] 82 c3 [2] 9e c4 [2] 82 eb }

  condition:
    any of them
}