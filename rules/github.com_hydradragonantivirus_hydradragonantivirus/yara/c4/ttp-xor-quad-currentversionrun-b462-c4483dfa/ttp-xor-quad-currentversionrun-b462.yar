rule TTP_XOR_QUAD_CurrentVersionRun_b462 {
  strings:
    $key_b462 = { e7 0d [2] c3 03 [2] e8 2f [2] c6 0d [2] d2 16 [2] dd 0c [2] c3 11 [2] c1 10 [2] da 16 [2] c6 11 [2] da 3e }

  condition:
    any of them
}