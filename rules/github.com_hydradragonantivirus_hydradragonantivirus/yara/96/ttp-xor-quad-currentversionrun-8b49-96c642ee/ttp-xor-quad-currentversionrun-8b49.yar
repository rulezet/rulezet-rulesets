rule TTP_XOR_QUAD_CurrentVersionRun_8b49 {
  strings:
    $key_8b49 = { d8 26 [2] fc 28 [2] d7 04 [2] f9 26 [2] ed 3d [2] e2 27 [2] fc 3a [2] fe 3b [2] e5 3d [2] f9 3a [2] e5 15 }

  condition:
    any of them
}