rule TTP_XOR_QUAD_CurrentVersionRun_8b48 {
  strings:
    $key_8b48 = { d8 27 [2] fc 29 [2] d7 05 [2] f9 27 [2] ed 3c [2] e2 26 [2] fc 3b [2] fe 3a [2] e5 3c [2] f9 3b [2] e5 14 }

  condition:
    any of them
}