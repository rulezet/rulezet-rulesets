rule TTP_XOR_QUAD_CurrentVersionRun_7084 {
  strings:
    $key_7084 = { 23 eb [2] 07 e5 [2] 2c c9 [2] 02 eb [2] 16 f0 [2] 19 ea [2] 07 f7 [2] 05 f6 [2] 1e f0 [2] 02 f7 [2] 1e d8 }

  condition:
    any of them
}