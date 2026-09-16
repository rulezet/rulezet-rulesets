rule TTP_XOR_QUAD_CurrentVersionRun_b1e4 {
  strings:
    $key_b1e4 = { e2 8b [2] c6 85 [2] ed a9 [2] c3 8b [2] d7 90 [2] d8 8a [2] c6 97 [2] c4 96 [2] df 90 [2] c3 97 [2] df b8 }

  condition:
    any of them
}