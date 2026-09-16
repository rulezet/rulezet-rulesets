rule TTP_XOR_QUAD_CurrentVersionRun_b35c {
  strings:
    $key_b35c = { e0 33 [2] c4 3d [2] ef 11 [2] c1 33 [2] d5 28 [2] da 32 [2] c4 2f [2] c6 2e [2] dd 28 [2] c1 2f [2] dd 00 }

  condition:
    any of them
}