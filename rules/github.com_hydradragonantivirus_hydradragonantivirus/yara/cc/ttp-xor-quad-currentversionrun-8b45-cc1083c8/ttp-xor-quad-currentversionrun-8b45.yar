rule TTP_XOR_QUAD_CurrentVersionRun_8b45 {
  strings:
    $key_8b45 = { d8 2a [2] fc 24 [2] d7 08 [2] f9 2a [2] ed 31 [2] e2 2b [2] fc 36 [2] fe 37 [2] e5 31 [2] f9 36 [2] e5 19 }

  condition:
    any of them
}