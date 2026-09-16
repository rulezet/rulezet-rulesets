rule TTP_XOR_QUAD_CurrentVersionRun_8b65 {
  strings:
    $key_8b65 = { d8 0a [2] fc 04 [2] d7 28 [2] f9 0a [2] ed 11 [2] e2 0b [2] fc 16 [2] fe 17 [2] e5 11 [2] f9 16 [2] e5 39 }

  condition:
    any of them
}