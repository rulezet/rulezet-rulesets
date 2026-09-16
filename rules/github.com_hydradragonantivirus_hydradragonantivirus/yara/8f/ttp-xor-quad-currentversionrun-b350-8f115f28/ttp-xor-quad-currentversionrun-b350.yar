rule TTP_XOR_QUAD_CurrentVersionRun_b350 {
  strings:
    $key_b350 = { e0 3f [2] c4 31 [2] ef 1d [2] c1 3f [2] d5 24 [2] da 3e [2] c4 23 [2] c6 22 [2] dd 24 [2] c1 23 [2] dd 0c }

  condition:
    any of them
}