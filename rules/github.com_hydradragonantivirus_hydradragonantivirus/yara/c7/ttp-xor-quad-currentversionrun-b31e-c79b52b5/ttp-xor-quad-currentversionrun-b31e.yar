rule TTP_XOR_QUAD_CurrentVersionRun_b31e {
  strings:
    $key_b31e = { e0 71 [2] c4 7f [2] ef 53 [2] c1 71 [2] d5 6a [2] da 70 [2] c4 6d [2] c6 6c [2] dd 6a [2] c1 6d [2] dd 42 }

  condition:
    any of them
}