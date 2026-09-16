rule TTP_XOR_QUAD_CurrentVersionRun_b316 {
  strings:
    $key_b316 = { e0 79 [2] c4 77 [2] ef 5b [2] c1 79 [2] d5 62 [2] da 78 [2] c4 65 [2] c6 64 [2] dd 62 [2] c1 65 [2] dd 4a }

  condition:
    any of them
}