rule TTP_XOR_QUAD_CurrentVersionRun_e184 {
  strings:
    $key_e184 = { b2 eb [2] 96 e5 [2] bd c9 [2] 93 eb [2] 87 f0 [2] 88 ea [2] 96 f7 [2] 94 f6 [2] 8f f0 [2] 93 f7 [2] 8f d8 }

  condition:
    any of them
}