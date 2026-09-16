rule TTP_XOR_QUAD_CurrentVersionRun_6084 {
  strings:
    $key_6084 = { 33 eb [2] 17 e5 [2] 3c c9 [2] 12 eb [2] 06 f0 [2] 09 ea [2] 17 f7 [2] 15 f6 [2] 0e f0 [2] 12 f7 [2] 0e d8 }

  condition:
    any of them
}