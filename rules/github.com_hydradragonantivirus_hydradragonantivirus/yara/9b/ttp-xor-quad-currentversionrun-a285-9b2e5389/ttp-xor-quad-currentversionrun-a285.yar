rule TTP_XOR_QUAD_CurrentVersionRun_a285 {
  strings:
    $key_a285 = { f1 ea [2] d5 e4 [2] fe c8 [2] d0 ea [2] c4 f1 [2] cb eb [2] d5 f6 [2] d7 f7 [2] cc f1 [2] d0 f6 [2] cc d9 }

  condition:
    any of them
}