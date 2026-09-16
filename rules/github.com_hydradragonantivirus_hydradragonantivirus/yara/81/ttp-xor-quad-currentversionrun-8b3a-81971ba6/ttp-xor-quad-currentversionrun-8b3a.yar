rule TTP_XOR_QUAD_CurrentVersionRun_8b3a {
  strings:
    $key_8b3a = { d8 55 [2] fc 5b [2] d7 77 [2] f9 55 [2] ed 4e [2] e2 54 [2] fc 49 [2] fe 48 [2] e5 4e [2] f9 49 [2] e5 66 }

  condition:
    any of them
}