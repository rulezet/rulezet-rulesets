rule TTP_XOR_QUAD_CurrentVersionRun_f084 {
  strings:
    $key_f084 = { a3 eb [2] 87 e5 [2] ac c9 [2] 82 eb [2] 96 f0 [2] 99 ea [2] 87 f7 [2] 85 f6 [2] 9e f0 [2] 82 f7 [2] 9e d8 }

  condition:
    any of them
}