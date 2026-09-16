rule TTP_XOR_QUAD_CurrentVersionRun_b3da {
  strings:
    $key_b3da = { e0 b5 [2] c4 bb [2] ef 97 [2] c1 b5 [2] d5 ae [2] da b4 [2] c4 a9 [2] c6 a8 [2] dd ae [2] c1 a9 [2] dd 86 }

  condition:
    any of them
}