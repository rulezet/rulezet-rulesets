rule TTP_XOR_QUAD_CurrentVersionRun_8b68 {
  strings:
    $key_8b68 = { d8 07 [2] fc 09 [2] d7 25 [2] f9 07 [2] ed 1c [2] e2 06 [2] fc 1b [2] fe 1a [2] e5 1c [2] f9 1b [2] e5 34 }

  condition:
    any of them
}