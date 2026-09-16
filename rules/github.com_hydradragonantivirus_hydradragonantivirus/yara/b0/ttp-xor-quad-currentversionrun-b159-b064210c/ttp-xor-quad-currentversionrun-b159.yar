rule TTP_XOR_QUAD_CurrentVersionRun_b159 {
  strings:
    $key_b159 = { e2 36 [2] c6 38 [2] ed 14 [2] c3 36 [2] d7 2d [2] d8 37 [2] c6 2a [2] c4 2b [2] df 2d [2] c3 2a [2] df 05 }

  condition:
    any of them
}