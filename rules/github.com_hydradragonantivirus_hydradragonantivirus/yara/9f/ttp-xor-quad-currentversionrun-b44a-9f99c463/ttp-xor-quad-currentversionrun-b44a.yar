rule TTP_XOR_QUAD_CurrentVersionRun_b44a {
  strings:
    $key_b44a = { e7 25 [2] c3 2b [2] e8 07 [2] c6 25 [2] d2 3e [2] dd 24 [2] c3 39 [2] c1 38 [2] da 3e [2] c6 39 [2] da 16 }

  condition:
    any of them
}