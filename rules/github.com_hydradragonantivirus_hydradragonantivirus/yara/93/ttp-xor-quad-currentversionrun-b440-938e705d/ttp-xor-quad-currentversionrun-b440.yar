rule TTP_XOR_QUAD_CurrentVersionRun_b440 {
  strings:
    $key_b440 = { e7 2f [2] c3 21 [2] e8 0d [2] c6 2f [2] d2 34 [2] dd 2e [2] c3 33 [2] c1 32 [2] da 34 [2] c6 33 [2] da 1c }

  condition:
    any of them
}