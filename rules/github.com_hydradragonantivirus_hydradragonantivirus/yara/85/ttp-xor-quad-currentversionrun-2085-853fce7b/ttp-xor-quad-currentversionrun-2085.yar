rule TTP_XOR_QUAD_CurrentVersionRun_2085 {
  strings:
    $key_2085 = { 73 ea [2] 57 e4 [2] 7c c8 [2] 52 ea [2] 46 f1 [2] 49 eb [2] 57 f6 [2] 55 f7 [2] 4e f1 [2] 52 f6 [2] 4e d9 }

  condition:
    any of them
}