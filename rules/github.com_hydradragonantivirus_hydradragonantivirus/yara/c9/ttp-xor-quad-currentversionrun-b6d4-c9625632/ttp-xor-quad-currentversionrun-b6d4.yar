rule TTP_XOR_QUAD_CurrentVersionRun_b6d4 {
  strings:
    $key_b6d4 = { e5 bb [2] c1 b5 [2] ea 99 [2] c4 bb [2] d0 a0 [2] df ba [2] c1 a7 [2] c3 a6 [2] d8 a0 [2] c4 a7 [2] d8 88 }

  condition:
    any of them
}