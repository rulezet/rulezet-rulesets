rule TTP_XOR_QUAD_CurrentVersionRun_b30e {
  strings:
    $key_b30e = { e0 61 [2] c4 6f [2] ef 43 [2] c1 61 [2] d5 7a [2] da 60 [2] c4 7d [2] c6 7c [2] dd 7a [2] c1 7d [2] dd 52 }

  condition:
    any of them
}