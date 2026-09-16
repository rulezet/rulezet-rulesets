rule TTP_XOR_QUAD_CurrentVersionRun_838e {
  strings:
    $key_838e = { d0 e1 [2] f4 ef [2] df c3 [2] f1 e1 [2] e5 fa [2] ea e0 [2] f4 fd [2] f6 fc [2] ed fa [2] f1 fd [2] ed d2 }

  condition:
    any of them
}