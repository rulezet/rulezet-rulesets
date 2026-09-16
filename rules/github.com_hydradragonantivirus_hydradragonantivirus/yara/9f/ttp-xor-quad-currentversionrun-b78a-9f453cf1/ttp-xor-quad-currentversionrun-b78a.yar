rule TTP_XOR_QUAD_CurrentVersionRun_b78a {
  strings:
    $key_b78a = { e4 e5 [2] c0 eb [2] eb c7 [2] c5 e5 [2] d1 fe [2] de e4 [2] c0 f9 [2] c2 f8 [2] d9 fe [2] c5 f9 [2] d9 d6 }

  condition:
    any of them
}