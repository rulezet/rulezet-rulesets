rule TTP_XOR_QUAD_CurrentVersionRun_b41a {
  strings:
    $key_b41a = { e7 75 [2] c3 7b [2] e8 57 [2] c6 75 [2] d2 6e [2] dd 74 [2] c3 69 [2] c1 68 [2] da 6e [2] c6 69 [2] da 46 }

  condition:
    any of them
}