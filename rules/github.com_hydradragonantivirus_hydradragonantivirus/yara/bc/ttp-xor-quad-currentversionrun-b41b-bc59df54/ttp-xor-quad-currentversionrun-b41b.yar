rule TTP_XOR_QUAD_CurrentVersionRun_b41b {
  strings:
    $key_b41b = { e7 74 [2] c3 7a [2] e8 56 [2] c6 74 [2] d2 6f [2] dd 75 [2] c3 68 [2] c1 69 [2] da 6f [2] c6 68 [2] da 47 }

  condition:
    any of them
}