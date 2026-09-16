rule TTP_XOR_QUAD_CurrentVersionRun_b310 {
  strings:
    $key_b310 = { e0 7f [2] c4 71 [2] ef 5d [2] c1 7f [2] d5 64 [2] da 7e [2] c4 63 [2] c6 62 [2] dd 64 [2] c1 63 [2] dd 4c }

  condition:
    any of them
}