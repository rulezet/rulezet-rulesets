rule TTP_XOR_QUAD_CurrentVersionRun_a299 {
  strings:
    $key_a299 = { f1 f6 [2] d5 f8 [2] fe d4 [2] d0 f6 [2] c4 ed [2] cb f7 [2] d5 ea [2] d7 eb [2] cc ed [2] d0 ea [2] cc c5 }

  condition:
    any of them
}