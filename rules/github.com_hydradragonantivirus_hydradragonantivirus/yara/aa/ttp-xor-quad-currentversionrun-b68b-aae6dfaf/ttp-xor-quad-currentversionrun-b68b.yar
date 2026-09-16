rule TTP_XOR_QUAD_CurrentVersionRun_b68b {
  strings:
    $key_b68b = { e5 e4 [2] c1 ea [2] ea c6 [2] c4 e4 [2] d0 ff [2] df e5 [2] c1 f8 [2] c3 f9 [2] d8 ff [2] c4 f8 [2] d8 d7 }

  condition:
    any of them
}