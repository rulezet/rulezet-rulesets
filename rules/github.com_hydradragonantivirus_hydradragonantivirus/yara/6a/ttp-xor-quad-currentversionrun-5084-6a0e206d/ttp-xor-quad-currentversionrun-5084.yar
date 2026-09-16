rule TTP_XOR_QUAD_CurrentVersionRun_5084 {
  strings:
    $key_5084 = { 03 eb [2] 27 e5 [2] 0c c9 [2] 22 eb [2] 36 f0 [2] 39 ea [2] 27 f7 [2] 25 f6 [2] 3e f0 [2] 22 f7 [2] 3e d8 }

  condition:
    any of them
}