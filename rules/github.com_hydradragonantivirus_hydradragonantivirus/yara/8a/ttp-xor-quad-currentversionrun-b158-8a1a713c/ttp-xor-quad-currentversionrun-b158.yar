rule TTP_XOR_QUAD_CurrentVersionRun_b158 {
  strings:
    $key_b158 = { e2 37 [2] c6 39 [2] ed 15 [2] c3 37 [2] d7 2c [2] d8 36 [2] c6 2b [2] c4 2a [2] df 2c [2] c3 2b [2] df 04 }

  condition:
    any of them
}