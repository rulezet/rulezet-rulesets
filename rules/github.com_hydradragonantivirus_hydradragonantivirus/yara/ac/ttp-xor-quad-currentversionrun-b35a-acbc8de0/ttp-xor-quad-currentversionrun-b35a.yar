rule TTP_XOR_QUAD_CurrentVersionRun_b35a {
  strings:
    $key_b35a = { e0 35 [2] c4 3b [2] ef 17 [2] c1 35 [2] d5 2e [2] da 34 [2] c4 29 [2] c6 28 [2] dd 2e [2] c1 29 [2] dd 06 }

  condition:
    any of them
}