rule TTP_XOR_QUAD_CurrentVersionRun_b415 {
  strings:
    $key_b415 = { e7 7a [2] c3 74 [2] e8 58 [2] c6 7a [2] d2 61 [2] dd 7b [2] c3 66 [2] c1 67 [2] da 61 [2] c6 66 [2] da 49 }

  condition:
    any of them
}