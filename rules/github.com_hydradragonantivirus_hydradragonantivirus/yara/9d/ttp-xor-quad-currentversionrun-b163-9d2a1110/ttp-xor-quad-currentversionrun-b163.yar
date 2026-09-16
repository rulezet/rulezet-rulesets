rule TTP_XOR_QUAD_CurrentVersionRun_b163 {
  strings:
    $key_b163 = { e2 0c [2] c6 02 [2] ed 2e [2] c3 0c [2] d7 17 [2] d8 0d [2] c6 10 [2] c4 11 [2] df 17 [2] c3 10 [2] df 3f }

  condition:
    any of them
}