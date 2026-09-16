rule TTP_XOR_QUAD_CurrentVersionRun_0185 {
  strings:
    $key_0185 = { 52 ea [2] 76 e4 [2] 5d c8 [2] 73 ea [2] 67 f1 [2] 68 eb [2] 76 f6 [2] 74 f7 [2] 6f f1 [2] 73 f6 [2] 6f d9 }

  condition:
    any of them
}