rule TTP_XOR_QUAD_CurrentVersionRun_b4ed {
  strings:
    $key_b4ed = { e7 82 [2] c3 8c [2] e8 a0 [2] c6 82 [2] d2 99 [2] dd 83 [2] c3 9e [2] c1 9f [2] da 99 [2] c6 9e [2] da b1 }

  condition:
    any of them
}