rule TTP_XOR_QUAD_CurrentVersionRun_b430 {
  strings:
    $key_b430 = { e7 5f [2] c3 51 [2] e8 7d [2] c6 5f [2] d2 44 [2] dd 5e [2] c3 43 [2] c1 42 [2] da 44 [2] c6 43 [2] da 6c }

  condition:
    any of them
}