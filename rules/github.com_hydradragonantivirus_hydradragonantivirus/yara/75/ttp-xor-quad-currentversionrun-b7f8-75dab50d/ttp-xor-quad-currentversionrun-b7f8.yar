rule TTP_XOR_QUAD_CurrentVersionRun_b7f8 {
  strings:
    $key_b7f8 = { e4 97 [2] c0 99 [2] eb b5 [2] c5 97 [2] d1 8c [2] de 96 [2] c0 8b [2] c2 8a [2] d9 8c [2] c5 8b [2] d9 a4 }

  condition:
    any of them
}