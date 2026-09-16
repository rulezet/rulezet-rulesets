rule TTP_XOR_QUAD_CurrentVersionRun_8b28 {
  strings:
    $key_8b28 = { d8 47 [2] fc 49 [2] d7 65 [2] f9 47 [2] ed 5c [2] e2 46 [2] fc 5b [2] fe 5a [2] e5 5c [2] f9 5b [2] e5 74 }

  condition:
    any of them
}