rule TTP_XOR_QUAD_CurrentVersionRun_b793 {
  strings:
    $key_b793 = { e4 fc [2] c0 f2 [2] eb de [2] c5 fc [2] d1 e7 [2] de fd [2] c0 e0 [2] c2 e1 [2] d9 e7 [2] c5 e0 [2] d9 cf }

  condition:
    any of them
}