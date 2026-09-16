rule TTP_XOR_QUAD_CurrentVersionRun_b7d2 {
  strings:
    $key_b7d2 = { e4 bd [2] c0 b3 [2] eb 9f [2] c5 bd [2] d1 a6 [2] de bc [2] c0 a1 [2] c2 a0 [2] d9 a6 [2] c5 a1 [2] d9 8e }

  condition:
    any of them
}