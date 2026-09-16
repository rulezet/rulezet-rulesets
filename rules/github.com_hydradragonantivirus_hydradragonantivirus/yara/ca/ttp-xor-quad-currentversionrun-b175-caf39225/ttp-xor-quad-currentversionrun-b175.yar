rule TTP_XOR_QUAD_CurrentVersionRun_b175 {
  strings:
    $key_b175 = { e2 1a [2] c6 14 [2] ed 38 [2] c3 1a [2] d7 01 [2] d8 1b [2] c6 06 [2] c4 07 [2] df 01 [2] c3 06 [2] df 29 }

  condition:
    any of them
}