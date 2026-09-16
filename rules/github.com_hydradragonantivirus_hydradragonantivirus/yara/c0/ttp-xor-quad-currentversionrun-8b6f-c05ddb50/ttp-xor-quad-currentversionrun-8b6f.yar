rule TTP_XOR_QUAD_CurrentVersionRun_8b6f {
  strings:
    $key_8b6f = { d8 00 [2] fc 0e [2] d7 22 [2] f9 00 [2] ed 1b [2] e2 01 [2] fc 1c [2] fe 1d [2] e5 1b [2] f9 1c [2] e5 33 }

  condition:
    any of them
}