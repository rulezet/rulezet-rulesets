rule TTP_XOR_QUAD_CurrentVersionRun_8b78 {
  strings:
    $key_8b78 = { d8 17 [2] fc 19 [2] d7 35 [2] f9 17 [2] ed 0c [2] e2 16 [2] fc 0b [2] fe 0a [2] e5 0c [2] f9 0b [2] e5 24 }

  condition:
    any of them
}