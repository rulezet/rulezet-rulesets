rule TTP_XOR_QUAD_CurrentVersionRun_8b19 {
  strings:
    $key_8b19 = { d8 76 [2] fc 78 [2] d7 54 [2] f9 76 [2] ed 6d [2] e2 77 [2] fc 6a [2] fe 6b [2] e5 6d [2] f9 6a [2] e5 45 }

  condition:
    any of them
}