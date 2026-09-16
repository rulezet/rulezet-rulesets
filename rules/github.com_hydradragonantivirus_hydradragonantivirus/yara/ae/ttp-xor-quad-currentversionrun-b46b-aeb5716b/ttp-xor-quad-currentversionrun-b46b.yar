rule TTP_XOR_QUAD_CurrentVersionRun_b46b {
  strings:
    $key_b46b = { e7 04 [2] c3 0a [2] e8 26 [2] c6 04 [2] d2 1f [2] dd 05 [2] c3 18 [2] c1 19 [2] da 1f [2] c6 18 [2] da 37 }

  condition:
    any of them
}