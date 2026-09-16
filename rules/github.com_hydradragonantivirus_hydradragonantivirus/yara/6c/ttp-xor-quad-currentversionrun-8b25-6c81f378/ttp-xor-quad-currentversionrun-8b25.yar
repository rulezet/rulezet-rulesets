rule TTP_XOR_QUAD_CurrentVersionRun_8b25 {
  strings:
    $key_8b25 = { d8 4a [2] fc 44 [2] d7 68 [2] f9 4a [2] ed 51 [2] e2 4b [2] fc 56 [2] fe 57 [2] e5 51 [2] f9 56 [2] e5 79 }

  condition:
    any of them
}