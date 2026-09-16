rule TTP_XOR_QUAD_CurrentVersionRun_b693 {
  strings:
    $key_b693 = { e5 fc [2] c1 f2 [2] ea de [2] c4 fc [2] d0 e7 [2] df fd [2] c1 e0 [2] c3 e1 [2] d8 e7 [2] c4 e0 [2] d8 cf }

  condition:
    any of them
}