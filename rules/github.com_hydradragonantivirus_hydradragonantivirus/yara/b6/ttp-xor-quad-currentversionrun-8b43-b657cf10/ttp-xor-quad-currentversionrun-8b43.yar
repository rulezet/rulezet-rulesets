rule TTP_XOR_QUAD_CurrentVersionRun_8b43 {
  strings:
    $key_8b43 = { d8 2c [2] fc 22 [2] d7 0e [2] f9 2c [2] ed 37 [2] e2 2d [2] fc 30 [2] fe 31 [2] e5 37 [2] f9 30 [2] e5 1f }

  condition:
    any of them
}