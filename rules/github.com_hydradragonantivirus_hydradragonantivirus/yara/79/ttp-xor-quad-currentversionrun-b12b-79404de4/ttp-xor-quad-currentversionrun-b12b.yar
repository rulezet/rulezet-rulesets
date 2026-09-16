rule TTP_XOR_QUAD_CurrentVersionRun_b12b {
  strings:
    $key_b12b = { e2 44 [2] c6 4a [2] ed 66 [2] c3 44 [2] d7 5f [2] d8 45 [2] c6 58 [2] c4 59 [2] df 5f [2] c3 58 [2] df 77 }

  condition:
    any of them
}