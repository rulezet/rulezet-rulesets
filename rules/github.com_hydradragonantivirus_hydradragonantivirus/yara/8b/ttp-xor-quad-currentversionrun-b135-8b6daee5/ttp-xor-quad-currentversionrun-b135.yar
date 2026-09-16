rule TTP_XOR_QUAD_CurrentVersionRun_b135 {
  strings:
    $key_b135 = { e2 5a [2] c6 54 [2] ed 78 [2] c3 5a [2] d7 41 [2] d8 5b [2] c6 46 [2] c4 47 [2] df 41 [2] c3 46 [2] df 69 }

  condition:
    any of them
}