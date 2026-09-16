rule TTP_XOR_QUAD_CurrentVersionRun_b177 {
  strings:
    $key_b177 = { e2 18 [2] c6 16 [2] ed 3a [2] c3 18 [2] d7 03 [2] d8 19 [2] c6 04 [2] c4 05 [2] df 03 [2] c3 04 [2] df 2b }

  condition:
    any of them
}