rule TTP_XOR_QUAD_CurrentVersionRun_b48e {
  strings:
    $key_b48e = { e7 e1 [2] c3 ef [2] e8 c3 [2] c6 e1 [2] d2 fa [2] dd e0 [2] c3 fd [2] c1 fc [2] da fa [2] c6 fd [2] da d2 }

  condition:
    any of them
}