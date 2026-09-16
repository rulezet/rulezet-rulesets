rule TTP_XOR_QUAD_CurrentVersionRun_a297 {
  strings:
    $key_a297 = { f1 f8 [2] d5 f6 [2] fe da [2] d0 f8 [2] c4 e3 [2] cb f9 [2] d5 e4 [2] d7 e5 [2] cc e3 [2] d0 e4 [2] cc cb }

  condition:
    any of them
}