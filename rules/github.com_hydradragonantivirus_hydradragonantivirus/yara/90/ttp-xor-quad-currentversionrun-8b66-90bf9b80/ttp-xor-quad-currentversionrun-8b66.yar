rule TTP_XOR_QUAD_CurrentVersionRun_8b66 {
  strings:
    $key_8b66 = { d8 09 [2] fc 07 [2] d7 2b [2] f9 09 [2] ed 12 [2] e2 08 [2] fc 15 [2] fe 14 [2] e5 12 [2] f9 15 [2] e5 3a }

  condition:
    any of them
}