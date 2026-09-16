rule TTP_XOR_QUAD_CurrentVersionRun_b116 {
  strings:
    $key_b116 = { e2 79 [2] c6 77 [2] ed 5b [2] c3 79 [2] d7 62 [2] d8 78 [2] c6 65 [2] c4 64 [2] df 62 [2] c3 65 [2] df 4a }

  condition:
    any of them
}