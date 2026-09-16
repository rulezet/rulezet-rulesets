rule TTP_XOR_QUAD_CurrentVersionRun_b7f9 {
  strings:
    $key_b7f9 = { e4 96 [2] c0 98 [2] eb b4 [2] c5 96 [2] d1 8d [2] de 97 [2] c0 8a [2] c2 8b [2] d9 8d [2] c5 8a [2] d9 a5 }

  condition:
    any of them
}