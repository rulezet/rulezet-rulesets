rule TTP_XOR_QUAD_CurrentVersionRun_b445 {
  strings:
    $key_b445 = { e7 2a [2] c3 24 [2] e8 08 [2] c6 2a [2] d2 31 [2] dd 2b [2] c3 36 [2] c1 37 [2] da 31 [2] c6 36 [2] da 19 }

  condition:
    any of them
}