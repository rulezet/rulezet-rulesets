rule TTP_XOR_QUAD_CurrentVersionRun_8b64 {
  strings:
    $key_8b64 = { d8 0b [2] fc 05 [2] d7 29 [2] f9 0b [2] ed 10 [2] e2 0a [2] fc 17 [2] fe 16 [2] e5 10 [2] f9 17 [2] e5 38 }

  condition:
    any of them
}