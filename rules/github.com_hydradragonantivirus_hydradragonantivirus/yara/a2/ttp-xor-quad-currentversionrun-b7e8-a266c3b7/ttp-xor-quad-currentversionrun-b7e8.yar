rule TTP_XOR_QUAD_CurrentVersionRun_b7e8 {
  strings:
    $key_b7e8 = { e4 87 [2] c0 89 [2] eb a5 [2] c5 87 [2] d1 9c [2] de 86 [2] c0 9b [2] c2 9a [2] d9 9c [2] c5 9b [2] d9 b4 }

  condition:
    any of them
}