rule TTP_XOR_QUAD_CurrentVersionRun_b174 {
  strings:
    $key_b174 = { e2 1b [2] c6 15 [2] ed 39 [2] c3 1b [2] d7 00 [2] d8 1a [2] c6 07 [2] c4 06 [2] df 00 [2] c3 07 [2] df 28 }

  condition:
    any of them
}