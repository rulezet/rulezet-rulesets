rule TTP_XOR_QUAD_CurrentVersionRun_b427 {
  strings:
    $key_b427 = { e7 48 [2] c3 46 [2] e8 6a [2] c6 48 [2] d2 53 [2] dd 49 [2] c3 54 [2] c1 55 [2] da 53 [2] c6 54 [2] da 7b }

  condition:
    any of them
}