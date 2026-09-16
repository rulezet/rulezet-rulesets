rule TTP_XOR_QUAD_CurrentVersionRun_39aa {
  strings:
    $key_39aa = { 6a c5 [2] 4e cb [2] 65 e7 [2] 4b c5 [2] 5f de [2] 50 c4 [2] 4e d9 [2] 4c d8 [2] 57 de [2] 4b d9 [2] 57 f6 }

  condition:
    any of them
}