rule TTP_XOR_QUAD_CurrentVersionRun_8b74 {
  strings:
    $key_8b74 = { d8 1b [2] fc 15 [2] d7 39 [2] f9 1b [2] ed 00 [2] e2 1a [2] fc 07 [2] fe 06 [2] e5 00 [2] f9 07 [2] e5 28 }

  condition:
    any of them
}