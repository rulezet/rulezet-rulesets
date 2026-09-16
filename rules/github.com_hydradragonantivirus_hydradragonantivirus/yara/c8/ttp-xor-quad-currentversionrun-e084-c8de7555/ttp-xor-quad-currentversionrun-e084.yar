rule TTP_XOR_QUAD_CurrentVersionRun_e084 {
  strings:
    $key_e084 = { b3 eb [2] 97 e5 [2] bc c9 [2] 92 eb [2] 86 f0 [2] 89 ea [2] 97 f7 [2] 95 f6 [2] 8e f0 [2] 92 f7 [2] 8e d8 }

  condition:
    any of them
}