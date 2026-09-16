rule TTP_XOR_QUAD_CurrentVersionRun_b42c {
  strings:
    $key_b42c = { e7 43 [2] c3 4d [2] e8 61 [2] c6 43 [2] d2 58 [2] dd 42 [2] c3 5f [2] c1 5e [2] da 58 [2] c6 5f [2] da 70 }

  condition:
    any of them
}