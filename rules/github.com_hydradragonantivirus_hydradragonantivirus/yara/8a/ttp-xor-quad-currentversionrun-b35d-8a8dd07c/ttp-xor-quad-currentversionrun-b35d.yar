rule TTP_XOR_QUAD_CurrentVersionRun_b35d {
  strings:
    $key_b35d = { e0 32 [2] c4 3c [2] ef 10 [2] c1 32 [2] d5 29 [2] da 33 [2] c4 2e [2] c6 2f [2] dd 29 [2] c1 2e [2] dd 01 }

  condition:
    any of them
}