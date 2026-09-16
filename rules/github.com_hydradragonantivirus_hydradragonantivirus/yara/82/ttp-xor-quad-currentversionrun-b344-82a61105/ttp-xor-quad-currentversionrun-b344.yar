rule TTP_XOR_QUAD_CurrentVersionRun_b344 {
  strings:
    $key_b344 = { e0 2b [2] c4 25 [2] ef 09 [2] c1 2b [2] d5 30 [2] da 2a [2] c4 37 [2] c6 36 [2] dd 30 [2] c1 37 [2] dd 18 }

  condition:
    any of them
}