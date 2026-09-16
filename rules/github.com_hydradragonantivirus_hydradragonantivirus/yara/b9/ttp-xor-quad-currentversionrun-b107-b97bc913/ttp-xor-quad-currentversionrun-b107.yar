rule TTP_XOR_QUAD_CurrentVersionRun_b107 {
  strings:
    $key_b107 = { e2 68 [2] c6 66 [2] ed 4a [2] c3 68 [2] d7 73 [2] d8 69 [2] c6 74 [2] c4 75 [2] df 73 [2] c3 74 [2] df 5b }

  condition:
    any of them
}