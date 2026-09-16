rule TTP_XOR_QUAD_CurrentVersionRun_b43b {
  strings:
    $key_b43b = { e7 54 [2] c3 5a [2] e8 76 [2] c6 54 [2] d2 4f [2] dd 55 [2] c3 48 [2] c1 49 [2] da 4f [2] c6 48 [2] da 67 }

  condition:
    any of them
}