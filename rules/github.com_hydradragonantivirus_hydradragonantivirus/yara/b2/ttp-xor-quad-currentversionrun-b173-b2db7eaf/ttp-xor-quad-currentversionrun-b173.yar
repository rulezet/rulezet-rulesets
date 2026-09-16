rule TTP_XOR_QUAD_CurrentVersionRun_b173 {
  strings:
    $key_b173 = { e2 1c [2] c6 12 [2] ed 3e [2] c3 1c [2] d7 07 [2] d8 1d [2] c6 00 [2] c4 01 [2] df 07 [2] c3 00 [2] df 2f }

  condition:
    any of them
}