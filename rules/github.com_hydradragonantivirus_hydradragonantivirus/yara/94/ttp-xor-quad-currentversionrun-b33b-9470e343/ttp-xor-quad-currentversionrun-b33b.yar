rule TTP_XOR_QUAD_CurrentVersionRun_b33b {
  strings:
    $key_b33b = { e0 54 [2] c4 5a [2] ef 76 [2] c1 54 [2] d5 4f [2] da 55 [2] c4 48 [2] c6 49 [2] dd 4f [2] c1 48 [2] dd 67 }

  condition:
    any of them
}