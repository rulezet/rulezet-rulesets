rule TTP_XOR_QUAD_CurrentVersionRun_b300 {
  strings:
    $key_b300 = { e0 6f [2] c4 61 [2] ef 4d [2] c1 6f [2] d5 74 [2] da 6e [2] c4 73 [2] c6 72 [2] dd 74 [2] c1 73 [2] dd 5c }

  condition:
    any of them
}