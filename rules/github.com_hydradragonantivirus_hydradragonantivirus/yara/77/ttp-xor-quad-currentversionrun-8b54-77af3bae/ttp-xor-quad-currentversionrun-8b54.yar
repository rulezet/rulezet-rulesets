rule TTP_XOR_QUAD_CurrentVersionRun_8b54 {
  strings:
    $key_8b54 = { d8 3b [2] fc 35 [2] d7 19 [2] f9 3b [2] ed 20 [2] e2 3a [2] fc 27 [2] fe 26 [2] e5 20 [2] f9 27 [2] e5 08 }

  condition:
    any of them
}