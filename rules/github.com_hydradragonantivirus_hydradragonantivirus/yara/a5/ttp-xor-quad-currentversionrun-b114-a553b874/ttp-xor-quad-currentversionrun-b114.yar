rule TTP_XOR_QUAD_CurrentVersionRun_b114 {
  strings:
    $key_b114 = { e2 7b [2] c6 75 [2] ed 59 [2] c3 7b [2] d7 60 [2] d8 7a [2] c6 67 [2] c4 66 [2] df 60 [2] c3 67 [2] df 48 }

  condition:
    any of them
}