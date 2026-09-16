rule TTP_XOR_QUAD_CurrentVersionRun_b167 {
  strings:
    $key_b167 = { e2 08 [2] c6 06 [2] ed 2a [2] c3 08 [2] d7 13 [2] d8 09 [2] c6 14 [2] c4 15 [2] df 13 [2] c3 14 [2] df 3b }

  condition:
    any of them
}