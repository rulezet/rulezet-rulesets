rule TTP_XOR_QUAD_CurrentVersionRun_b085 {
  strings:
    $key_b085 = { e3 ea [2] c7 e4 [2] ec c8 [2] c2 ea [2] d6 f1 [2] d9 eb [2] c7 f6 [2] c5 f7 [2] de f1 [2] c2 f6 [2] de d9 }

  condition:
    any of them
}