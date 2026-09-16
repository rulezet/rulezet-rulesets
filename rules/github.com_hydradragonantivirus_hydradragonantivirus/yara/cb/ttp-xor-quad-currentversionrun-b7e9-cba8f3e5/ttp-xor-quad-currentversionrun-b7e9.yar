rule TTP_XOR_QUAD_CurrentVersionRun_b7e9 {
  strings:
    $key_b7e9 = { e4 86 [2] c0 88 [2] eb a4 [2] c5 86 [2] d1 9d [2] de 87 [2] c0 9a [2] c2 9b [2] d9 9d [2] c5 9a [2] d9 b5 }

  condition:
    any of them
}