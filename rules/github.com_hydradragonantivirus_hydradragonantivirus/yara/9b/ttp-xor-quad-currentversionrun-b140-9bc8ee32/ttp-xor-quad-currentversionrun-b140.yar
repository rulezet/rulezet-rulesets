rule TTP_XOR_QUAD_CurrentVersionRun_b140 {
  strings:
    $key_b140 = { e2 2f [2] c6 21 [2] ed 0d [2] c3 2f [2] d7 34 [2] d8 2e [2] c6 33 [2] c4 32 [2] df 34 [2] c3 33 [2] df 1c }

  condition:
    any of them
}