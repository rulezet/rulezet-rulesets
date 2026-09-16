rule TTP_XOR_QUAD_CurrentVersionRun_8b2b {
  strings:
    $key_8b2b = { d8 44 [2] fc 4a [2] d7 66 [2] f9 44 [2] ed 5f [2] e2 45 [2] fc 58 [2] fe 59 [2] e5 5f [2] f9 58 [2] e5 77 }

  condition:
    any of them
}