rule TTP_XOR_QUAD_CurrentVersionRun_a284 {
  strings:
    $key_a284 = { f1 eb [2] d5 e5 [2] fe c9 [2] d0 eb [2] c4 f0 [2] cb ea [2] d5 f7 [2] d7 f6 [2] cc f0 [2] d0 f7 [2] cc d8 }

  condition:
    any of them
}