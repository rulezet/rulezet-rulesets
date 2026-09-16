rule TTP_XOR_QUAD_CurrentVersionRun_b401 {
  strings:
    $key_b401 = { e7 6e [2] c3 60 [2] e8 4c [2] c6 6e [2] d2 75 [2] dd 6f [2] c3 72 [2] c1 73 [2] da 75 [2] c6 72 [2] da 5d }

  condition:
    any of them
}