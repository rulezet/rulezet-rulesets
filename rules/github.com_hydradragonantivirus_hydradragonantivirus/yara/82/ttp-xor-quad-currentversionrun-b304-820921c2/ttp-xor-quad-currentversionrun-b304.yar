rule TTP_XOR_QUAD_CurrentVersionRun_b304 {
  strings:
    $key_b304 = { e0 6b [2] c4 65 [2] ef 49 [2] c1 6b [2] d5 70 [2] da 6a [2] c4 77 [2] c6 76 [2] dd 70 [2] c1 77 [2] dd 58 }

  condition:
    any of them
}