rule TTP_XOR_QUAD_CurrentVersionRun_b313 {
  strings:
    $key_b313 = { e0 7c [2] c4 72 [2] ef 5e [2] c1 7c [2] d5 67 [2] da 7d [2] c4 60 [2] c6 61 [2] dd 67 [2] c1 60 [2] dd 4f }

  condition:
    any of them
}