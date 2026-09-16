rule TTP_XOR_QUAD_CurrentVersionRun_b320 {
  strings:
    $key_b320 = { e0 4f [2] c4 41 [2] ef 6d [2] c1 4f [2] d5 54 [2] da 4e [2] c4 53 [2] c6 52 [2] dd 54 [2] c1 53 [2] dd 7c }

  condition:
    any of them
}