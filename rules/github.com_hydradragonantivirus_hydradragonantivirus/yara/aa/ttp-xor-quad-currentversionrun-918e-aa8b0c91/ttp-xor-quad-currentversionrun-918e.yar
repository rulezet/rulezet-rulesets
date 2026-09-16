rule TTP_XOR_QUAD_CurrentVersionRun_918e {
  strings:
    $key_918e = { c2 e1 [2] e6 ef [2] cd c3 [2] e3 e1 [2] f7 fa [2] f8 e0 [2] e6 fd [2] e4 fc [2] ff fa [2] e3 fd [2] ff d2 }

  condition:
    any of them
}