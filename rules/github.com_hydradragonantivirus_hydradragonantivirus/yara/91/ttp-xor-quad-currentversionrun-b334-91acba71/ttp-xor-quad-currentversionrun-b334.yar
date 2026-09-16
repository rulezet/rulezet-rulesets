rule TTP_XOR_QUAD_CurrentVersionRun_b334 {
  strings:
    $key_b334 = { e0 5b [2] c4 55 [2] ef 79 [2] c1 5b [2] d5 40 [2] da 5a [2] c4 47 [2] c6 46 [2] dd 40 [2] c1 47 [2] dd 68 }

  condition:
    any of them
}