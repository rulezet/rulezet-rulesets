rule TTP_XOR_QUAD_CurrentVersionRun_8b5e {
  strings:
    $key_8b5e = { d8 31 [2] fc 3f [2] d7 13 [2] f9 31 [2] ed 2a [2] e2 30 [2] fc 2d [2] fe 2c [2] e5 2a [2] f9 2d [2] e5 02 }

  condition:
    any of them
}