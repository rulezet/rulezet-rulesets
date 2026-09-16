rule TTP_XOR_QUAD_CurrentVersionRun_5185 {
  strings:
    $key_5185 = { 02 ea [2] 26 e4 [2] 0d c8 [2] 23 ea [2] 37 f1 [2] 38 eb [2] 26 f6 [2] 24 f7 [2] 3f f1 [2] 23 f6 [2] 3f d9 }

  condition:
    any of them
}