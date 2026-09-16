rule TTP_XOR_QUAD_CurrentVersionRun_b142 {
  strings:
    $key_b142 = { e2 2d [2] c6 23 [2] ed 0f [2] c3 2d [2] d7 36 [2] d8 2c [2] c6 31 [2] c4 30 [2] df 36 [2] c3 31 [2] df 1e }

  condition:
    any of them
}