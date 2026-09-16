rule TTP_XOR_QUAD_CurrentVersionRun_8b69 {
  strings:
    $key_8b69 = { d8 06 [2] fc 08 [2] d7 24 [2] f9 06 [2] ed 1d [2] e2 07 [2] fc 1a [2] fe 1b [2] e5 1d [2] f9 1a [2] e5 35 }

  condition:
    any of them
}