rule TTP_XOR_QUAD_CurrentVersionRun_b166 {
  strings:
    $key_b166 = { e2 09 [2] c6 07 [2] ed 2b [2] c3 09 [2] d7 12 [2] d8 08 [2] c6 15 [2] c4 14 [2] df 12 [2] c3 15 [2] df 3a }

  condition:
    any of them
}