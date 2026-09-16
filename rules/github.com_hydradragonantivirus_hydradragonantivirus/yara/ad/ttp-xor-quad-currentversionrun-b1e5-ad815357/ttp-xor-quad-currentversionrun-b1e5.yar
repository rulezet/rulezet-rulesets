rule TTP_XOR_QUAD_CurrentVersionRun_b1e5 {
  strings:
    $key_b1e5 = { e2 8a [2] c6 84 [2] ed a8 [2] c3 8a [2] d7 91 [2] d8 8b [2] c6 96 [2] c4 97 [2] df 91 [2] c3 96 [2] df b9 }

  condition:
    any of them
}