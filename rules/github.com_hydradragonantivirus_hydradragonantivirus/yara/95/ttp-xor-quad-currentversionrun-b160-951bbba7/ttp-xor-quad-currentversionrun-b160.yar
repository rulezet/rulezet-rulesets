rule TTP_XOR_QUAD_CurrentVersionRun_b160 {
  strings:
    $key_b160 = { e2 0f [2] c6 01 [2] ed 2d [2] c3 0f [2] d7 14 [2] d8 0e [2] c6 13 [2] c4 12 [2] df 14 [2] c3 13 [2] df 3c }

  condition:
    any of them
}