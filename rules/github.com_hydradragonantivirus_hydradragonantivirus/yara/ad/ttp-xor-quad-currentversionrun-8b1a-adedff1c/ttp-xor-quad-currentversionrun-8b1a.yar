rule TTP_XOR_QUAD_CurrentVersionRun_8b1a {
  strings:
    $key_8b1a = { d8 75 [2] fc 7b [2] d7 57 [2] f9 75 [2] ed 6e [2] e2 74 [2] fc 69 [2] fe 68 [2] e5 6e [2] f9 69 [2] e5 46 }

  condition:
    any of them
}