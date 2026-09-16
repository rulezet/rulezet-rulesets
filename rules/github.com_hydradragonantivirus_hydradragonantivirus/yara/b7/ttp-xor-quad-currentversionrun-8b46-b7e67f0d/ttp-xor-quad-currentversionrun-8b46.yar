rule TTP_XOR_QUAD_CurrentVersionRun_8b46 {
  strings:
    $key_8b46 = { d8 29 [2] fc 27 [2] d7 0b [2] f9 29 [2] ed 32 [2] e2 28 [2] fc 35 [2] fe 34 [2] e5 32 [2] f9 35 [2] e5 1a }

  condition:
    any of them
}