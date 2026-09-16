rule TTP_XOR_QUAD_CurrentVersionRun_b18e {
  strings:
    $key_b18e = { e2 e1 [2] c6 ef [2] ed c3 [2] c3 e1 [2] d7 fa [2] d8 e0 [2] c6 fd [2] c4 fc [2] df fa [2] c3 fd [2] df d2 }

  condition:
    any of them
}