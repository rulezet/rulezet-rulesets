rule TTP_XOR_QUAD_CurrentVersionRun_b146 {
  strings:
    $key_b146 = { e2 29 [2] c6 27 [2] ed 0b [2] c3 29 [2] d7 32 [2] d8 28 [2] c6 35 [2] c4 34 [2] df 32 [2] c3 35 [2] df 1a }

  condition:
    any of them
}