rule TTP_XOR_QUAD_CurrentVersionRun_8d8e {
  strings:
    $key_8d8e = { de e1 [2] fa ef [2] d1 c3 [2] ff e1 [2] eb fa [2] e4 e0 [2] fa fd [2] f8 fc [2] e3 fa [2] ff fd [2] e3 d2 }

  condition:
    any of them
}