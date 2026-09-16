rule TTP_XOR_QUAD_CurrentVersionRun_b364 {
  strings:
    $key_b364 = { e0 0b [2] c4 05 [2] ef 29 [2] c1 0b [2] d5 10 [2] da 0a [2] c4 17 [2] c6 16 [2] dd 10 [2] c1 17 [2] dd 38 }

  condition:
    any of them
}