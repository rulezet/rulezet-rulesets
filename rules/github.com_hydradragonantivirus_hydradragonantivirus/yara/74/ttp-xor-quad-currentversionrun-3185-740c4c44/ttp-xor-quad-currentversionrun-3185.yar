rule TTP_XOR_QUAD_CurrentVersionRun_3185 {
  strings:
    $key_3185 = { 62 ea [2] 46 e4 [2] 6d c8 [2] 43 ea [2] 57 f1 [2] 58 eb [2] 46 f6 [2] 44 f7 [2] 5f f1 [2] 43 f6 [2] 5f d9 }

  condition:
    any of them
}