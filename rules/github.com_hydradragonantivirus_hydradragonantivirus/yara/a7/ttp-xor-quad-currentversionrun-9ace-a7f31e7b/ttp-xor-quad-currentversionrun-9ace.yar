rule TTP_XOR_QUAD_CurrentVersionRun_9ace {
  strings:
    $key_9ace = { c9 a1 [2] ed af [2] c6 83 [2] e8 a1 [2] fc ba [2] f3 a0 [2] ed bd [2] ef bc [2] f4 ba [2] e8 bd [2] f4 92 }

  condition:
    any of them
}