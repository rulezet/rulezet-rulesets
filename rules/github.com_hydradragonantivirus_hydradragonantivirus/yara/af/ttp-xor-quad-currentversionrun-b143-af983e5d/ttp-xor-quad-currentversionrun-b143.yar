rule TTP_XOR_QUAD_CurrentVersionRun_b143 {
  strings:
    $key_b143 = { e2 2c [2] c6 22 [2] ed 0e [2] c3 2c [2] d7 37 [2] d8 2d [2] c6 30 [2] c4 31 [2] df 37 [2] c3 30 [2] df 1f }

  condition:
    any of them
}