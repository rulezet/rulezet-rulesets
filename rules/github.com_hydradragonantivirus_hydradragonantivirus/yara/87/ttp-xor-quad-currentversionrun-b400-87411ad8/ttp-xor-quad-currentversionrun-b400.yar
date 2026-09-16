rule TTP_XOR_QUAD_CurrentVersionRun_b400 {
  strings:
    $key_b400 = { e7 6f [2] c3 61 [2] e8 4d [2] c6 6f [2] d2 74 [2] dd 6e [2] c3 73 [2] c1 72 [2] da 74 [2] c6 73 [2] da 5c }

  condition:
    any of them
}