rule TTP_XOR_QUAD_CurrentVersionRun_b422 {
  strings:
    $key_b422 = { e7 4d [2] c3 43 [2] e8 6f [2] c6 4d [2] d2 56 [2] dd 4c [2] c3 51 [2] c1 50 [2] da 56 [2] c6 51 [2] da 7e }

  condition:
    any of them
}