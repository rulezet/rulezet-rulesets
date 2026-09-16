rule TTP_XOR_QUAD_CurrentVersionRun_b6c7 {
  strings:
    $key_b6c7 = { e5 a8 [2] c1 a6 [2] ea 8a [2] c4 a8 [2] d0 b3 [2] df a9 [2] c1 b4 [2] c3 b5 [2] d8 b3 [2] c4 b4 [2] d8 9b }

  condition:
    any of them
}