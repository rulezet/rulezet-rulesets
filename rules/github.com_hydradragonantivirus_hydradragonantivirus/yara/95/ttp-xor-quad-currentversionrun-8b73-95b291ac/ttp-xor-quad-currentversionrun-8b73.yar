rule TTP_XOR_QUAD_CurrentVersionRun_8b73 {
  strings:
    $key_8b73 = { d8 1c [2] fc 12 [2] d7 3e [2] f9 1c [2] ed 07 [2] e2 1d [2] fc 00 [2] fe 01 [2] e5 07 [2] f9 00 [2] e5 2f }

  condition:
    any of them
}