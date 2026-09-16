rule TTP_XOR_QUAD_CurrentVersionRun_7085 {
  strings:
    $key_7085 = { 23 ea [2] 07 e4 [2] 2c c8 [2] 02 ea [2] 16 f1 [2] 19 eb [2] 07 f6 [2] 05 f7 [2] 1e f1 [2] 02 f6 [2] 1e d9 }

  condition:
    any of them
}