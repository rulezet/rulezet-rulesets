rule TTP_XOR_QUAD_CurrentVersionRun_b106 {
  strings:
    $key_b106 = { e2 69 [2] c6 67 [2] ed 4b [2] c3 69 [2] d7 72 [2] d8 68 [2] c6 75 [2] c4 74 [2] df 72 [2] c3 75 [2] df 5a }

  condition:
    any of them
}