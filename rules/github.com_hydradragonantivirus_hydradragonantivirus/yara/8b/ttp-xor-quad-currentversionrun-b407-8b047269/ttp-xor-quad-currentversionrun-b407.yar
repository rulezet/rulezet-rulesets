rule TTP_XOR_QUAD_CurrentVersionRun_b407 {
  strings:
    $key_b407 = { e7 68 [2] c3 66 [2] e8 4a [2] c6 68 [2] d2 73 [2] dd 69 [2] c3 74 [2] c1 75 [2] da 73 [2] c6 74 [2] da 5b }

  condition:
    any of them
}