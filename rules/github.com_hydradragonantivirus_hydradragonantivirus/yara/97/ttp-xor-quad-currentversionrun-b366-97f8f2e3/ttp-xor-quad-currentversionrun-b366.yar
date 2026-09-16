rule TTP_XOR_QUAD_CurrentVersionRun_b366 {
  strings:
    $key_b366 = { e0 09 [2] c4 07 [2] ef 2b [2] c1 09 [2] d5 12 [2] da 08 [2] c4 15 [2] c6 14 [2] dd 12 [2] c1 15 [2] dd 3a }

  condition:
    any of them
}