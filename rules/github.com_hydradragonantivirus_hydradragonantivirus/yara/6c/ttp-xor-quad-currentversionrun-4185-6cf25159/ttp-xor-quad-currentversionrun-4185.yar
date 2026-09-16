rule TTP_XOR_QUAD_CurrentVersionRun_4185 {
  strings:
    $key_4185 = { 12 ea [2] 36 e4 [2] 1d c8 [2] 33 ea [2] 27 f1 [2] 28 eb [2] 36 f6 [2] 34 f7 [2] 2f f1 [2] 33 f6 [2] 2f d9 }

  condition:
    any of them
}