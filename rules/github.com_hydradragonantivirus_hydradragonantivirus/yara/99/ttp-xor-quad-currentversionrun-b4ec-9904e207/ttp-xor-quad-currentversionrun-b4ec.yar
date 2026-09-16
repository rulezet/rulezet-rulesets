rule TTP_XOR_QUAD_CurrentVersionRun_b4ec {
  strings:
    $key_b4ec = { e7 83 [2] c3 8d [2] e8 a1 [2] c6 83 [2] d2 98 [2] dd 82 [2] c3 9f [2] c1 9e [2] da 98 [2] c6 9f [2] da b0 }

  condition:
    any of them
}