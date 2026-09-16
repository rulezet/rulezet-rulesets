rule TTP_XOR_QUAD_CurrentVersionRun_8b18 {
  strings:
    $key_8b18 = { d8 77 [2] fc 79 [2] d7 55 [2] f9 77 [2] ed 6c [2] e2 76 [2] fc 6b [2] fe 6a [2] e5 6c [2] f9 6b [2] e5 44 }

  condition:
    any of them
}