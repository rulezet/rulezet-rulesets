rule TTP_XOR_QUAD_CurrentVersionRun_b433 {
  strings:
    $key_b433 = { e7 5c [2] c3 52 [2] e8 7e [2] c6 5c [2] d2 47 [2] dd 5d [2] c3 40 [2] c1 41 [2] da 47 [2] c6 40 [2] da 6f }

  condition:
    any of them
}