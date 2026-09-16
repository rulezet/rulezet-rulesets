rule TTP_XOR_QUAD_CurrentVersionRun_b308 {
  strings:
    $key_b308 = { e0 67 [2] c4 69 [2] ef 45 [2] c1 67 [2] d5 7c [2] da 66 [2] c4 7b [2] c6 7a [2] dd 7c [2] c1 7b [2] dd 54 }

  condition:
    any of them
}