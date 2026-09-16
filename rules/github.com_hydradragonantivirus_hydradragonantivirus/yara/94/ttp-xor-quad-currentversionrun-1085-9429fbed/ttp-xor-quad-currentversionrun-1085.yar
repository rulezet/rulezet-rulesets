rule TTP_XOR_QUAD_CurrentVersionRun_1085 {
  strings:
    $key_1085 = { 43 ea [2] 67 e4 [2] 4c c8 [2] 62 ea [2] 76 f1 [2] 79 eb [2] 67 f6 [2] 65 f7 [2] 7e f1 [2] 62 f6 [2] 7e d9 }

  condition:
    any of them
}