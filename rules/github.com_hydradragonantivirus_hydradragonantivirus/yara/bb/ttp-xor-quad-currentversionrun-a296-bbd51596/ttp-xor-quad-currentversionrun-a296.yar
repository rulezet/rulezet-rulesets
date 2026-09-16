rule TTP_XOR_QUAD_CurrentVersionRun_a296 {
  strings:
    $key_a296 = { f1 f9 [2] d5 f7 [2] fe db [2] d0 f9 [2] c4 e2 [2] cb f8 [2] d5 e5 [2] d7 e4 [2] cc e2 [2] d0 e5 [2] cc ca }

  condition:
    any of them
}