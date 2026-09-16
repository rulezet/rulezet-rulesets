rule TTP_XOR_QUAD_CurrentVersionRun_a385 {
  strings:
    $key_a385 = { f0 ea [2] d4 e4 [2] ff c8 [2] d1 ea [2] c5 f1 [2] ca eb [2] d4 f6 [2] d6 f7 [2] cd f1 [2] d1 f6 [2] cd d9 }

  condition:
    any of them
}