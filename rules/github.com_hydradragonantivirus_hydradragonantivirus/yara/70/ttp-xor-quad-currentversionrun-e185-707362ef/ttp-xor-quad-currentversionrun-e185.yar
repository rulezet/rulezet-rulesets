rule TTP_XOR_QUAD_CurrentVersionRun_e185 {
  strings:
    $key_e185 = { b2 ea [2] 96 e4 [2] bd c8 [2] 93 ea [2] 87 f1 [2] 88 eb [2] 96 f6 [2] 94 f7 [2] 8f f1 [2] 93 f6 [2] 8f d9 }

  condition:
    any of them
}