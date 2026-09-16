rule TTP_XOR_QUAD_CurrentVersionRun_b311 {
  strings:
    $key_b311 = { e0 7e [2] c4 70 [2] ef 5c [2] c1 7e [2] d5 65 [2] da 7f [2] c4 62 [2] c6 63 [2] dd 65 [2] c1 62 [2] dd 4d }

  condition:
    any of them
}