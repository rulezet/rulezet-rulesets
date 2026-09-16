rule TTP_XOR_QUAD_CurrentVersionRun_b332 {
  strings:
    $key_b332 = { e0 5d [2] c4 53 [2] ef 7f [2] c1 5d [2] d5 46 [2] da 5c [2] c4 41 [2] c6 40 [2] dd 46 [2] c1 41 [2] dd 6e }

  condition:
    any of them
}