rule TTP_XOR_QUAD_CurrentVersionRun_b16b {
  strings:
    $key_b16b = { e2 04 [2] c6 0a [2] ed 26 [2] c3 04 [2] d7 1f [2] d8 05 [2] c6 18 [2] c4 19 [2] df 1f [2] c3 18 [2] df 37 }

  condition:
    any of them
}