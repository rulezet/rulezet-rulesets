rule TTP_XOR_QUAD_CurrentVersionRun_b7e4 {
  strings:
    $key_b7e4 = { e4 8b [2] c0 85 [2] eb a9 [2] c5 8b [2] d1 90 [2] de 8a [2] c0 97 [2] c2 96 [2] d9 90 [2] c5 97 [2] d9 b8 }

  condition:
    any of them
}