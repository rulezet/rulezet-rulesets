rule TTP_XOR_QUAD_CurrentVersionRun_b4fd {
  strings:
    $key_b4fd = { e7 92 [2] c3 9c [2] e8 b0 [2] c6 92 [2] d2 89 [2] dd 93 [2] c3 8e [2] c1 8f [2] da 89 [2] c6 8e [2] da a1 }

  condition:
    any of them
}