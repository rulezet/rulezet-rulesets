rule TTP_XOR_QUAD_CurrentVersionRun_b779 {
  strings:
    $key_b779 = { e4 16 [2] c0 18 [2] eb 34 [2] c5 16 [2] d1 0d [2] de 17 [2] c0 0a [2] c2 0b [2] d9 0d [2] c5 0a [2] d9 25 }

  condition:
    any of them
}