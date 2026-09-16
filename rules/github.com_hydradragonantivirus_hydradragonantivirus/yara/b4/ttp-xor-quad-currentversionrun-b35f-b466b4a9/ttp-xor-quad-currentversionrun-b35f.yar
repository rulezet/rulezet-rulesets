rule TTP_XOR_QUAD_CurrentVersionRun_b35f {
  strings:
    $key_b35f = { e0 30 [2] c4 3e [2] ef 12 [2] c1 30 [2] d5 2b [2] da 31 [2] c4 2c [2] c6 2d [2] dd 2b [2] c1 2c [2] dd 03 }

  condition:
    any of them
}