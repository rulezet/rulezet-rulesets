rule TTP_XOR_QUAD_CurrentVersionRun_518e {
  strings:
    $key_518e = { 02 e1 [2] 26 ef [2] 0d c3 [2] 23 e1 [2] 37 fa [2] 38 e0 [2] 26 fd [2] 24 fc [2] 3f fa [2] 23 fd [2] 3f d2 }

  condition:
    any of them
}