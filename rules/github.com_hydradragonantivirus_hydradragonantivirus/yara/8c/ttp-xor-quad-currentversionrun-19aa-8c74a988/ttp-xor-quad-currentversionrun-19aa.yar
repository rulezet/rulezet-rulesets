rule TTP_XOR_QUAD_CurrentVersionRun_19aa {
  strings:
    $key_19aa = { 4a c5 [2] 6e cb [2] 45 e7 [2] 6b c5 [2] 7f de [2] 70 c4 [2] 6e d9 [2] 6c d8 [2] 77 de [2] 6b d9 [2] 77 f6 }

  condition:
    any of them
}