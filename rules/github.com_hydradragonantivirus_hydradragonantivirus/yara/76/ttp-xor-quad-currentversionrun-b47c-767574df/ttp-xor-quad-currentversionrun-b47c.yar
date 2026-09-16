rule TTP_XOR_QUAD_CurrentVersionRun_b47c {
  strings:
    $key_b47c = { e7 13 [2] c3 1d [2] e8 31 [2] c6 13 [2] d2 08 [2] dd 12 [2] c3 0f [2] c1 0e [2] da 08 [2] c6 0f [2] da 20 }

  condition:
    any of them
}