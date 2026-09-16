rule TTP_XOR_QUAD_CurrentVersionRun_3285 {
  strings:
    $key_3285 = { 61 ea [2] 45 e4 [2] 6e c8 [2] 40 ea [2] 54 f1 [2] 5b eb [2] 45 f6 [2] 47 f7 [2] 5c f1 [2] 40 f6 [2] 5c d9 }

  condition:
    any of them
}