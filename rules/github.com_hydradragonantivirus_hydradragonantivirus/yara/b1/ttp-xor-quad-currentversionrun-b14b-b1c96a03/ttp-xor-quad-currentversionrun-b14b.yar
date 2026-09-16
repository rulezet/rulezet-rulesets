rule TTP_XOR_QUAD_CurrentVersionRun_b14b {
  strings:
    $key_b14b = { e2 24 [2] c6 2a [2] ed 06 [2] c3 24 [2] d7 3f [2] d8 25 [2] c6 38 [2] c4 39 [2] df 3f [2] c3 38 [2] df 17 }

  condition:
    any of them
}