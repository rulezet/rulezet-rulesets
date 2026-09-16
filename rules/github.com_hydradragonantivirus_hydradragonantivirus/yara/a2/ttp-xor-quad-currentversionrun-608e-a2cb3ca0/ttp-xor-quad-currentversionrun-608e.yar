rule TTP_XOR_QUAD_CurrentVersionRun_608e {
  strings:
    $key_608e = { 33 e1 [2] 17 ef [2] 3c c3 [2] 12 e1 [2] 06 fa [2] 09 e0 [2] 17 fd [2] 15 fc [2] 0e fa [2] 12 fd [2] 0e d2 }

  condition:
    any of them
}