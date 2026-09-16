rule TTP_XOR_QUAD_CurrentVersionRun_b161 {
  strings:
    $key_b161 = { e2 0e [2] c6 00 [2] ed 2c [2] c3 0e [2] d7 15 [2] d8 0f [2] c6 12 [2] c4 13 [2] df 15 [2] c3 12 [2] df 3d }

  condition:
    any of them
}