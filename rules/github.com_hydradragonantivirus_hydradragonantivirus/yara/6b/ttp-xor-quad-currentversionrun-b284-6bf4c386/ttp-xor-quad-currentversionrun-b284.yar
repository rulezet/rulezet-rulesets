rule TTP_XOR_QUAD_CurrentVersionRun_b284 {
  strings:
    $key_b284 = { e1 eb [2] c5 e5 [2] ee c9 [2] c0 eb [2] d4 f0 [2] db ea [2] c5 f7 [2] c7 f6 [2] dc f0 [2] c0 f7 [2] dc d8 }

  condition:
    any of them
}