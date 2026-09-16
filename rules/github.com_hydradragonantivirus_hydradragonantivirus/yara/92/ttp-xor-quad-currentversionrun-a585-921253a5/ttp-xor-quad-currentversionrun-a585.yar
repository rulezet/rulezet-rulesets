rule TTP_XOR_QUAD_CurrentVersionRun_a585 {
  strings:
    $key_a585 = { f6 ea [2] d2 e4 [2] f9 c8 [2] d7 ea [2] c3 f1 [2] cc eb [2] d2 f6 [2] d0 f7 [2] cb f1 [2] d7 f6 [2] cb d9 }

  condition:
    any of them
}