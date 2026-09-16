rule TTP_XOR_QUAD_CurrentVersionRun_b34d {
  strings:
    $key_b34d = { e0 22 [2] c4 2c [2] ef 00 [2] c1 22 [2] d5 39 [2] da 23 [2] c4 3e [2] c6 3f [2] dd 39 [2] c1 3e [2] dd 11 }

  condition:
    any of them
}