rule TTP_XOR_QUAD_CurrentVersionRun_548e {
  strings:
    $key_548e = { 07 e1 [2] 23 ef [2] 08 c3 [2] 26 e1 [2] 32 fa [2] 3d e0 [2] 23 fd [2] 21 fc [2] 3a fa [2] 26 fd [2] 3a d2 }

  condition:
    any of them
}