rule TTP_XOR_QUAD_CurrentVersionRun_b7d1 {
  strings:
    $key_b7d1 = { e4 be [2] c0 b0 [2] eb 9c [2] c5 be [2] d1 a5 [2] de bf [2] c0 a2 [2] c2 a3 [2] d9 a5 [2] c5 a2 [2] d9 8d }

  condition:
    any of them
}