rule TTP_XOR_QUAD_CurrentVersionRun_b408 {
  strings:
    $key_b408 = { e7 67 [2] c3 69 [2] e8 45 [2] c6 67 [2] d2 7c [2] dd 66 [2] c3 7b [2] c1 7a [2] da 7c [2] c6 7b [2] da 54 }

  condition:
    any of them
}