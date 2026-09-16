rule TTP_XOR_QUAD_CurrentVersionRun_b365 {
  strings:
    $key_b365 = { e0 0a [2] c4 04 [2] ef 28 [2] c1 0a [2] d5 11 [2] da 0b [2] c4 16 [2] c6 17 [2] dd 11 [2] c1 16 [2] dd 39 }

  condition:
    any of them
}