rule TTP_XOR_QUAD_CurrentVersionRun_b7e6 {
  strings:
    $key_b7e6 = { e4 89 [2] c0 87 [2] eb ab [2] c5 89 [2] d1 92 [2] de 88 [2] c0 95 [2] c2 94 [2] d9 92 [2] c5 95 [2] d9 ba }

  condition:
    any of them
}