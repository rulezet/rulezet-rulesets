rule TTP_XOR_QUAD_CurrentVersionRun_a784 {
  strings:
    $key_a784 = { f4 eb [2] d0 e5 [2] fb c9 [2] d5 eb [2] c1 f0 [2] ce ea [2] d0 f7 [2] d2 f6 [2] c9 f0 [2] d5 f7 [2] c9 d8 }

  condition:
    any of them
}