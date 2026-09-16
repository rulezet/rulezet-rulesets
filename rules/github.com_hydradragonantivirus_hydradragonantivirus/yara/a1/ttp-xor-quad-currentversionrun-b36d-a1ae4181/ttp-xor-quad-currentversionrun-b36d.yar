rule TTP_XOR_QUAD_CurrentVersionRun_b36d {
  strings:
    $key_b36d = { e0 02 [2] c4 0c [2] ef 20 [2] c1 02 [2] d5 19 [2] da 03 [2] c4 1e [2] c6 1f [2] dd 19 [2] c1 1e [2] dd 31 }

  condition:
    any of them
}