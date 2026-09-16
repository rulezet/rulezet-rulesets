rule TTP_XOR_QUAD_CurrentVersionRun_b185 {
  strings:
    $key_b185 = { e2 ea [2] c6 e4 [2] ed c8 [2] c3 ea [2] d7 f1 [2] d8 eb [2] c6 f6 [2] c4 f7 [2] df f1 [2] c3 f6 [2] df d9 }

  condition:
    any of them
}