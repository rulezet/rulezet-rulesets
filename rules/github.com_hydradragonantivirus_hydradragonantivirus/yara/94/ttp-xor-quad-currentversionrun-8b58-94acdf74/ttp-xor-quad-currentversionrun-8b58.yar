rule TTP_XOR_QUAD_CurrentVersionRun_8b58 {
  strings:
    $key_8b58 = { d8 37 [2] fc 39 [2] d7 15 [2] f9 37 [2] ed 2c [2] e2 36 [2] fc 2b [2] fe 2a [2] e5 2c [2] f9 2b [2] e5 04 }

  condition:
    any of them
}