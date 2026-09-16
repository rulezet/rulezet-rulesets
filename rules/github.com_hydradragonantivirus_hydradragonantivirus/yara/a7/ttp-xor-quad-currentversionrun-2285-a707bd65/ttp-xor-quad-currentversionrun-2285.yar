rule TTP_XOR_QUAD_CurrentVersionRun_2285 {
  strings:
    $key_2285 = { 71 ea [2] 55 e4 [2] 7e c8 [2] 50 ea [2] 44 f1 [2] 4b eb [2] 55 f6 [2] 57 f7 [2] 4c f1 [2] 50 f6 [2] 4c d9 }

  condition:
    any of them
}