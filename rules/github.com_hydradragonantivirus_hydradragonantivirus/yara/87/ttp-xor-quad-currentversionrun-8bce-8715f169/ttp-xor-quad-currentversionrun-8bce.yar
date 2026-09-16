rule TTP_XOR_QUAD_CurrentVersionRun_8bce {
  strings:
    $key_8bce = { d8 a1 [2] fc af [2] d7 83 [2] f9 a1 [2] ed ba [2] e2 a0 [2] fc bd [2] fe bc [2] e5 ba [2] f9 bd [2] e5 92 }

  condition:
    any of them
}