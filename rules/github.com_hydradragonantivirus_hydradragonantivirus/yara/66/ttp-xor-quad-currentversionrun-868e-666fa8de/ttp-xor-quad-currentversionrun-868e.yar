rule TTP_XOR_QUAD_CurrentVersionRun_868e {
  strings:
    $key_868e = { d5 e1 [2] f1 ef [2] da c3 [2] f4 e1 [2] e0 fa [2] ef e0 [2] f1 fd [2] f3 fc [2] e8 fa [2] f4 fd [2] e8 d2 }

  condition:
    any of them
}