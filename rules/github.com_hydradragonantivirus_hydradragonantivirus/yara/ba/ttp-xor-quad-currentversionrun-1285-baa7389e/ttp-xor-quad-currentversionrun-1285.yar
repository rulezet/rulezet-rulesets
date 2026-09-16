rule TTP_XOR_QUAD_CurrentVersionRun_1285 {
  strings:
    $key_1285 = { 41 ea [2] 65 e4 [2] 4e c8 [2] 60 ea [2] 74 f1 [2] 7b eb [2] 65 f6 [2] 67 f7 [2] 7c f1 [2] 60 f6 [2] 7c d9 }

  condition:
    any of them
}