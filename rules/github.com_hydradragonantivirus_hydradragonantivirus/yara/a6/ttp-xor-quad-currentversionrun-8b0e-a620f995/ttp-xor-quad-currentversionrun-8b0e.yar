rule TTP_XOR_QUAD_CurrentVersionRun_8b0e {
  strings:
    $key_8b0e = { d8 61 [2] fc 6f [2] d7 43 [2] f9 61 [2] ed 7a [2] e2 60 [2] fc 7d [2] fe 7c [2] e5 7a [2] f9 7d [2] e5 52 }

  condition:
    any of them
}