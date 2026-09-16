rule TTP_XOR_QUAD_CurrentVersionRun_b145 {
  strings:
    $key_b145 = { e2 2a [2] c6 24 [2] ed 08 [2] c3 2a [2] d7 31 [2] d8 2b [2] c6 36 [2] c4 37 [2] df 31 [2] c3 36 [2] df 19 }

  condition:
    any of them
}