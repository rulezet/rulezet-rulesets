rule TTP_XOR_QUAD_CurrentVersionRun_b4e9 {
  strings:
    $key_b4e9 = { e7 86 [2] c3 88 [2] e8 a4 [2] c6 86 [2] d2 9d [2] dd 87 [2] c3 9a [2] c1 9b [2] da 9d [2] c6 9a [2] da b5 }

  condition:
    any of them
}