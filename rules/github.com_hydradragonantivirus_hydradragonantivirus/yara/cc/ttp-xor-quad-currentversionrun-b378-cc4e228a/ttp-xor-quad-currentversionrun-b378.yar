rule TTP_XOR_QUAD_CurrentVersionRun_b378 {
  strings:
    $key_b378 = { e0 17 [2] c4 19 [2] ef 35 [2] c1 17 [2] d5 0c [2] da 16 [2] c4 0b [2] c6 0a [2] dd 0c [2] c1 0b [2] dd 24 }

  condition:
    any of them
}