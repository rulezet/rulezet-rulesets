rule TTP_XOR_QUAD_CurrentVersionRun_b42d {
  strings:
    $key_b42d = { e7 42 [2] c3 4c [2] e8 60 [2] c6 42 [2] d2 59 [2] dd 43 [2] c3 5e [2] c1 5f [2] da 59 [2] c6 5e [2] da 71 }

  condition:
    any of them
}