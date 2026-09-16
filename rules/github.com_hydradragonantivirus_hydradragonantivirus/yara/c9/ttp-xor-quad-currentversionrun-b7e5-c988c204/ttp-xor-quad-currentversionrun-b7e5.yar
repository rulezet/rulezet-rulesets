rule TTP_XOR_QUAD_CurrentVersionRun_b7e5 {
  strings:
    $key_b7e5 = { e4 8a [2] c0 84 [2] eb a8 [2] c5 8a [2] d1 91 [2] de 8b [2] c0 96 [2] c2 97 [2] d9 91 [2] c5 96 [2] d9 b9 }

  condition:
    any of them
}