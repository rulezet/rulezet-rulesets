rule TTP_XOR_QUAD_CurrentVersionRun_348e {
  strings:
    $key_348e = { 67 e1 [2] 43 ef [2] 68 c3 [2] 46 e1 [2] 52 fa [2] 5d e0 [2] 43 fd [2] 41 fc [2] 5a fa [2] 46 fd [2] 5a d2 }

  condition:
    any of them
}