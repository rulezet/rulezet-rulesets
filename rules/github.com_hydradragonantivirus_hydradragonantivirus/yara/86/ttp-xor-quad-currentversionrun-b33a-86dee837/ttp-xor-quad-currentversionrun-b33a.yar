rule TTP_XOR_QUAD_CurrentVersionRun_b33a {
  strings:
    $key_b33a = { e0 55 [2] c4 5b [2] ef 77 [2] c1 55 [2] d5 4e [2] da 54 [2] c4 49 [2] c6 48 [2] dd 4e [2] c1 49 [2] dd 66 }

  condition:
    any of them
}