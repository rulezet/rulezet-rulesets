rule TTP_XOR_QUAD_CurrentVersionRun_b45d {
  strings:
    $key_b45d = { e7 32 [2] c3 3c [2] e8 10 [2] c6 32 [2] d2 29 [2] dd 33 [2] c3 2e [2] c1 2f [2] da 29 [2] c6 2e [2] da 01 }

  condition:
    any of them
}