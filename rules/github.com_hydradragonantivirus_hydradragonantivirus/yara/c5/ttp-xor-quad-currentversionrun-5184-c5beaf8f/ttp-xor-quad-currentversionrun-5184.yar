rule TTP_XOR_QUAD_CurrentVersionRun_5184 {
  strings:
    $key_5184 = { 02 eb [2] 26 e5 [2] 0d c9 [2] 23 eb [2] 37 f0 [2] 38 ea [2] 26 f7 [2] 24 f6 [2] 3f f0 [2] 23 f7 [2] 3f d8 }

  condition:
    any of them
}