rule TTP_XOR_QUAD_CurrentVersionRun_b38a {
  strings:
    $key_b38a = { e0 e5 [2] c4 eb [2] ef c7 [2] c1 e5 [2] d5 fe [2] da e4 [2] c4 f9 [2] c6 f8 [2] dd fe [2] c1 f9 [2] dd d6 }

  condition:
    any of them
}