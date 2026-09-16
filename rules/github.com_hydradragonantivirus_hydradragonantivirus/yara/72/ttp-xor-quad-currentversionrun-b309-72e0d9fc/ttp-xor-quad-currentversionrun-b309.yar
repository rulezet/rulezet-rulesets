rule TTP_XOR_QUAD_CurrentVersionRun_b309 {
  strings:
    $key_b309 = { e0 66 [2] c4 68 [2] ef 44 [2] c1 66 [2] d5 7d [2] da 67 [2] c4 7a [2] c6 7b [2] dd 7d [2] c1 7a [2] dd 55 }

  condition:
    any of them
}