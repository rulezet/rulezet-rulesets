rule TTP_XOR_QUAD_CurrentVersionRun_b164 {
  strings:
    $key_b164 = { e2 0b [2] c6 05 [2] ed 29 [2] c3 0b [2] d7 10 [2] d8 0a [2] c6 17 [2] c4 16 [2] df 10 [2] c3 17 [2] df 38 }

  condition:
    any of them
}