rule TTP_XOR_QUAD_CurrentVersionRun_b715 {
  strings:
    $key_b715 = { e4 7a [2] c0 74 [2] eb 58 [2] c5 7a [2] d1 61 [2] de 7b [2] c0 66 [2] c2 67 [2] d9 61 [2] c5 66 [2] d9 49 }

  condition:
    any of them
}