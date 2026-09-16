rule TTP_XOR_QUAD_CurrentVersionRun_8b55 {
  strings:
    $key_8b55 = { d8 3a [2] fc 34 [2] d7 18 [2] f9 3a [2] ed 21 [2] e2 3b [2] fc 26 [2] fe 27 [2] e5 21 [2] f9 26 [2] e5 09 }

  condition:
    any of them
}