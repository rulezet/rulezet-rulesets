rule TTP_XOR_QUAD_CurrentVersionRun_b339 {
  strings:
    $key_b339 = { e0 56 [2] c4 58 [2] ef 74 [2] c1 56 [2] d5 4d [2] da 57 [2] c4 4a [2] c6 4b [2] dd 4d [2] c1 4a [2] dd 65 }

  condition:
    any of them
}