rule TTP_XOR_QUAD_CurrentVersionRun_208e {
  strings:
    $key_208e = { 73 e1 [2] 57 ef [2] 7c c3 [2] 52 e1 [2] 46 fa [2] 49 e0 [2] 57 fd [2] 55 fc [2] 4e fa [2] 52 fd [2] 4e d2 }

  condition:
    any of them
}