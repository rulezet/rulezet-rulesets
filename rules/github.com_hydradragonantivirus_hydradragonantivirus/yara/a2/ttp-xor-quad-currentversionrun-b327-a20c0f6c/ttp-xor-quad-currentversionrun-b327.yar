rule TTP_XOR_QUAD_CurrentVersionRun_b327 {
  strings:
    $key_b327 = { e0 48 [2] c4 46 [2] ef 6a [2] c1 48 [2] d5 53 [2] da 49 [2] c4 54 [2] c6 55 [2] dd 53 [2] c1 54 [2] dd 7b }

  condition:
    any of them
}