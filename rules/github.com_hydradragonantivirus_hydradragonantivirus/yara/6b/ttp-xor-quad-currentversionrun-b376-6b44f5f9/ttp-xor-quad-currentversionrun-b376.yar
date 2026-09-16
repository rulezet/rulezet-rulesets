rule TTP_XOR_QUAD_CurrentVersionRun_b376 {
  strings:
    $key_b376 = { e0 19 [2] c4 17 [2] ef 3b [2] c1 19 [2] d5 02 [2] da 18 [2] c4 05 [2] c6 04 [2] dd 02 [2] c1 05 [2] dd 2a }

  condition:
    any of them
}