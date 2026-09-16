rule TTP_XOR_QUAD_CurrentVersionRun_b336 {
  strings:
    $key_b336 = { e0 59 [2] c4 57 [2] ef 7b [2] c1 59 [2] d5 42 [2] da 58 [2] c4 45 [2] c6 44 [2] dd 42 [2] c1 45 [2] dd 6a }

  condition:
    any of them
}