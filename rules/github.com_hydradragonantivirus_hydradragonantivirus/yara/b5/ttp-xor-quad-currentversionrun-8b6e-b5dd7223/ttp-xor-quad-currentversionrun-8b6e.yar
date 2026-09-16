rule TTP_XOR_QUAD_CurrentVersionRun_8b6e {
  strings:
    $key_8b6e = { d8 01 [2] fc 0f [2] d7 23 [2] f9 01 [2] ed 1a [2] e2 00 [2] fc 1d [2] fe 1c [2] e5 1a [2] f9 1d [2] e5 32 }

  condition:
    any of them
}