rule TTP_XOR_QUAD_CurrentVersionRun_8b27 {
  strings:
    $key_8b27 = { d8 48 [2] fc 46 [2] d7 6a [2] f9 48 [2] ed 53 [2] e2 49 [2] fc 54 [2] fe 55 [2] e5 53 [2] f9 54 [2] e5 7b }

  condition:
    any of them
}