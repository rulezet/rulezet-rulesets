rule TTP_XOR_QUAD_CurrentVersionRun_218e {
  strings:
    $key_218e = { 72 e1 [2] 56 ef [2] 7d c3 [2] 53 e1 [2] 47 fa [2] 48 e0 [2] 56 fd [2] 54 fc [2] 4f fa [2] 53 fd [2] 4f d2 }

  condition:
    any of them
}