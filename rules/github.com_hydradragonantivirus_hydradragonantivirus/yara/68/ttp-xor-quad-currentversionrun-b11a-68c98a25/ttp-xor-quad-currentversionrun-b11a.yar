rule TTP_XOR_QUAD_CurrentVersionRun_b11a {
  strings:
    $key_b11a = { e2 75 [2] c6 7b [2] ed 57 [2] c3 75 [2] d7 6e [2] d8 74 [2] c6 69 [2] c4 68 [2] df 6e [2] c3 69 [2] df 46 }

  condition:
    any of them
}