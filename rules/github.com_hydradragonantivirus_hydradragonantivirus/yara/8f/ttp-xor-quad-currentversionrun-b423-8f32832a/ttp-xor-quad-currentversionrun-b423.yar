rule TTP_XOR_QUAD_CurrentVersionRun_b423 {
  strings:
    $key_b423 = { e7 4c [2] c3 42 [2] e8 6e [2] c6 4c [2] d2 57 [2] dd 4d [2] c3 50 [2] c1 51 [2] da 57 [2] c6 50 [2] da 7f }

  condition:
    any of them
}