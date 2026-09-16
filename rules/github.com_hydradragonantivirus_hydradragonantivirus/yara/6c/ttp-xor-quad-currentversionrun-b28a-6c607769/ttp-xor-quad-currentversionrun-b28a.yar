rule TTP_XOR_QUAD_CurrentVersionRun_b28a {
  strings:
    $key_b28a = { e1 e5 [2] c5 eb [2] ee c7 [2] c0 e5 [2] d4 fe [2] db e4 [2] c5 f9 [2] c7 f8 [2] dc fe [2] c0 f9 [2] dc d6 }

  condition:
    any of them
}