rule TTP_XOR_QUAD_CurrentVersionRun_8b52 {
  strings:
    $key_8b52 = { d8 3d [2] fc 33 [2] d7 1f [2] f9 3d [2] ed 26 [2] e2 3c [2] fc 21 [2] fe 20 [2] e5 26 [2] f9 21 [2] e5 0e }

  condition:
    any of them
}