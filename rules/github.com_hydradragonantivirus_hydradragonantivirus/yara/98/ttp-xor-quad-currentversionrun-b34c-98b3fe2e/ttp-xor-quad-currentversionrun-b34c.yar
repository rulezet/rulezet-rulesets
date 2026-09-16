rule TTP_XOR_QUAD_CurrentVersionRun_b34c {
  strings:
    $key_b34c = { e0 23 [2] c4 2d [2] ef 01 [2] c1 23 [2] d5 38 [2] da 22 [2] c4 3f [2] c6 3e [2] dd 38 [2] c1 3f [2] dd 10 }

  condition:
    any of them
}