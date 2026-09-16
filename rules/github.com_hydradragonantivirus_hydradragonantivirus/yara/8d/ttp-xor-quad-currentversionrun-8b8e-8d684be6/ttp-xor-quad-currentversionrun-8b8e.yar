rule TTP_XOR_QUAD_CurrentVersionRun_8b8e {
  strings:
    $key_8b8e = { d8 e1 [2] fc ef [2] d7 c3 [2] f9 e1 [2] ed fa [2] e2 e0 [2] fc fd [2] fe fc [2] e5 fa [2] f9 fd [2] e5 d2 }

  condition:
    any of them
}