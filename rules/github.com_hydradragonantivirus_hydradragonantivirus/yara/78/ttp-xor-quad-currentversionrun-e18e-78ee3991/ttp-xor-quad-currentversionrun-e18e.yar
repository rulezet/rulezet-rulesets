rule TTP_XOR_QUAD_CurrentVersionRun_e18e {
  strings:
    $key_e18e = { b2 e1 [2] 96 ef [2] bd c3 [2] 93 e1 [2] 87 fa [2] 88 e0 [2] 96 fd [2] 94 fc [2] 8f fa [2] 93 fd [2] 8f d2 }

  condition:
    any of them
}