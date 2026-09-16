rule TTP_XOR_QUAD_CurrentVersionRun_b404 {
  strings:
    $key_b404 = { e7 6b [2] c3 65 [2] e8 49 [2] c6 6b [2] d2 70 [2] dd 6a [2] c3 77 [2] c1 76 [2] da 70 [2] c6 77 [2] da 58 }

  condition:
    any of them
}