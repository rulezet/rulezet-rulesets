rule TTP_XOR_QUAD_CurrentVersionRun_b324 {
  strings:
    $key_b324 = { e0 4b [2] c4 45 [2] ef 69 [2] c1 4b [2] d5 50 [2] da 4a [2] c4 57 [2] c6 56 [2] dd 50 [2] c1 57 [2] dd 78 }

  condition:
    any of them
}