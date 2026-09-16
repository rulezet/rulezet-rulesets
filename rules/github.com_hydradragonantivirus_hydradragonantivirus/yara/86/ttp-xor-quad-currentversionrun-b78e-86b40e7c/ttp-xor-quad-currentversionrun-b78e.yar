rule TTP_XOR_QUAD_CurrentVersionRun_b78e {
  strings:
    $key_b78e = { e4 e1 [2] c0 ef [2] eb c3 [2] c5 e1 [2] d1 fa [2] de e0 [2] c0 fd [2] c2 fc [2] d9 fa [2] c5 fd [2] d9 d2 }

  condition:
    any of them
}