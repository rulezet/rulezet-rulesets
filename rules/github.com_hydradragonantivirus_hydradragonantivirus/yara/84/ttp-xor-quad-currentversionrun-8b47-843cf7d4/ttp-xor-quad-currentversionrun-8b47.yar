rule TTP_XOR_QUAD_CurrentVersionRun_8b47 {
  strings:
    $key_8b47 = { d8 28 [2] fc 26 [2] d7 0a [2] f9 28 [2] ed 33 [2] e2 29 [2] fc 34 [2] fe 35 [2] e5 33 [2] f9 34 [2] e5 1b }

  condition:
    any of them
}