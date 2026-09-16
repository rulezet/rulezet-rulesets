rule TTP_XOR_QUAD_CurrentVersionRun_b126 {
  strings:
    $key_b126 = { e2 49 [2] c6 47 [2] ed 6b [2] c3 49 [2] d7 52 [2] d8 48 [2] c6 55 [2] c4 54 [2] df 52 [2] c3 55 [2] df 7a }

  condition:
    any of them
}