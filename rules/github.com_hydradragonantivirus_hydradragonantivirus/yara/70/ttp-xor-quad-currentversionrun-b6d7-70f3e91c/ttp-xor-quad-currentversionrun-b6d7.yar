rule TTP_XOR_QUAD_CurrentVersionRun_b6d7 {
  strings:
    $key_b6d7 = { e5 b8 [2] c1 b6 [2] ea 9a [2] c4 b8 [2] d0 a3 [2] df b9 [2] c1 a4 [2] c3 a5 [2] d8 a3 [2] c4 a4 [2] d8 8b }

  condition:
    any of them
}