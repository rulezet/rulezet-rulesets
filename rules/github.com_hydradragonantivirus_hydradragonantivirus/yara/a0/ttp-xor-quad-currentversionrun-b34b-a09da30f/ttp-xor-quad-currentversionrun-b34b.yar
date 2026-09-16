rule TTP_XOR_QUAD_CurrentVersionRun_b34b {
  strings:
    $key_b34b = { e0 24 [2] c4 2a [2] ef 06 [2] c1 24 [2] d5 3f [2] da 25 [2] c4 38 [2] c6 39 [2] dd 3f [2] c1 38 [2] dd 17 }

  condition:
    any of them
}