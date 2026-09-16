rule TTP_XOR_QUAD_CurrentVersionRun_b493 {
  strings:
    $key_b493 = { e7 fc [2] c3 f2 [2] e8 de [2] c6 fc [2] d2 e7 [2] dd fd [2] c3 e0 [2] c1 e1 [2] da e7 [2] c6 e0 [2] da cf }

  condition:
    any of them
}