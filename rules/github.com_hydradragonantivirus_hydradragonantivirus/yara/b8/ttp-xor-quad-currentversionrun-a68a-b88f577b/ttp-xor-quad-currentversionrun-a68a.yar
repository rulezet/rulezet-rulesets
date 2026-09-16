rule TTP_XOR_QUAD_CurrentVersionRun_a68a {
  strings:
    $key_a68a = { f5 e5 [2] d1 eb [2] fa c7 [2] d4 e5 [2] c0 fe [2] cf e4 [2] d1 f9 [2] d3 f8 [2] c8 fe [2] d4 f9 [2] c8 d6 }

  condition:
    any of them
}