rule TTP_XOR_QUAD_CurrentVersionRun_b37e {
  strings:
    $key_b37e = { e0 11 [2] c4 1f [2] ef 33 [2] c1 11 [2] d5 0a [2] da 10 [2] c4 0d [2] c6 0c [2] dd 0a [2] c1 0d [2] dd 22 }

  condition:
    any of them
}