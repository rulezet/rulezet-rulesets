rule TTP_XOR_QUAD_CurrentVersionRun_8b72 {
  strings:
    $key_8b72 = { d8 1d [2] fc 13 [2] d7 3f [2] f9 1d [2] ed 06 [2] e2 1c [2] fc 01 [2] fe 00 [2] e5 06 [2] f9 01 [2] e5 2e }

  condition:
    any of them
}