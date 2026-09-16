rule TTP_XOR_QUAD_CurrentVersionRun_b28b {
  strings:
    $key_b28b = { e1 e4 [2] c5 ea [2] ee c6 [2] c0 e4 [2] d4 ff [2] db e5 [2] c5 f8 [2] c7 f9 [2] dc ff [2] c0 f8 [2] dc d7 }

  condition:
    any of them
}