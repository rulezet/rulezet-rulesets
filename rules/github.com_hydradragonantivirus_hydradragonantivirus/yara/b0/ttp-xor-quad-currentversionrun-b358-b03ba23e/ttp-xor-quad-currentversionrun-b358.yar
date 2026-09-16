rule TTP_XOR_QUAD_CurrentVersionRun_b358 {
  strings:
    $key_b358 = { e0 37 [2] c4 39 [2] ef 15 [2] c1 37 [2] d5 2c [2] da 36 [2] c4 2b [2] c6 2a [2] dd 2c [2] c1 2b [2] dd 04 }

  condition:
    any of them
}