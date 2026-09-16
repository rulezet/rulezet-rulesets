rule TTP_XOR_QUAD_CurrentVersionRun_8b61 {
  strings:
    $key_8b61 = { d8 0e [2] fc 00 [2] d7 2c [2] f9 0e [2] ed 15 [2] e2 0f [2] fc 12 [2] fe 13 [2] e5 15 [2] f9 12 [2] e5 3d }

  condition:
    any of them
}