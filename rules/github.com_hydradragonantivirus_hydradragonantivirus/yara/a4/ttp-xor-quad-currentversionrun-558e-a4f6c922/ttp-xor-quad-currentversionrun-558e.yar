rule TTP_XOR_QUAD_CurrentVersionRun_558e {
  strings:
    $key_558e = { 06 e1 [2] 22 ef [2] 09 c3 [2] 27 e1 [2] 33 fa [2] 3c e0 [2] 22 fd [2] 20 fc [2] 3b fa [2] 27 fd [2] 3b d2 }

  condition:
    any of them
}