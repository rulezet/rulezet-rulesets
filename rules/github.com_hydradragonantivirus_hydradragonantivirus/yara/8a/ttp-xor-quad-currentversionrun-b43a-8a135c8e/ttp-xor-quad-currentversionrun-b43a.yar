rule TTP_XOR_QUAD_CurrentVersionRun_b43a {
  strings:
    $key_b43a = { e7 55 [2] c3 5b [2] e8 77 [2] c6 55 [2] d2 4e [2] dd 54 [2] c3 49 [2] c1 48 [2] da 4e [2] c6 49 [2] da 66 }

  condition:
    any of them
}