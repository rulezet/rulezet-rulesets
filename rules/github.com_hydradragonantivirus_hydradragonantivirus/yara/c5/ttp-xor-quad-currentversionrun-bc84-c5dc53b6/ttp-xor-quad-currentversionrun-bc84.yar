rule TTP_XOR_QUAD_CurrentVersionRun_bc84 {
  strings:
    $key_bc84 = { ef eb [2] cb e5 [2] e0 c9 [2] ce eb [2] da f0 [2] d5 ea [2] cb f7 [2] c9 f6 [2] d2 f0 [2] ce f7 [2] d2 d8 }

  condition:
    any of them
}