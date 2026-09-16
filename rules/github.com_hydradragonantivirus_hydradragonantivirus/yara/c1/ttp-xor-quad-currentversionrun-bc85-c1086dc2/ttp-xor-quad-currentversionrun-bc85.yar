rule TTP_XOR_QUAD_CurrentVersionRun_bc85 {
  strings:
    $key_bc85 = { ef ea [2] cb e4 [2] e0 c8 [2] ce ea [2] da f1 [2] d5 eb [2] cb f6 [2] c9 f7 [2] d2 f1 [2] ce f6 [2] d2 d9 }

  condition:
    any of them
}