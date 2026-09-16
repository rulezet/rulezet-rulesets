rule TTP_XOR_QUAD_CurrentVersionRun_b1d1 {
  strings:
    $key_b1d1 = { e2 be [2] c6 b0 [2] ed 9c [2] c3 be [2] d7 a5 [2] d8 bf [2] c6 a2 [2] c4 a3 [2] df a5 [2] c3 a2 [2] df 8d }

  condition:
    any of them
}