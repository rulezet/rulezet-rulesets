rule TTP_XOR_QUAD_CurrentVersionRun_b40a {
  strings:
    $key_b40a = { e7 65 [2] c3 6b [2] e8 47 [2] c6 65 [2] d2 7e [2] dd 64 [2] c3 79 [2] c1 78 [2] da 7e [2] c6 79 [2] da 56 }

  condition:
    any of them
}