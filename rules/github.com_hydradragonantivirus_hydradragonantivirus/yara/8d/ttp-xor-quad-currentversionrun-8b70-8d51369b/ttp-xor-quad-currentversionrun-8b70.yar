rule TTP_XOR_QUAD_CurrentVersionRun_8b70 {
  strings:
    $key_8b70 = { d8 1f [2] fc 11 [2] d7 3d [2] f9 1f [2] ed 04 [2] e2 1e [2] fc 03 [2] fe 02 [2] e5 04 [2] f9 03 [2] e5 2c }

  condition:
    any of them
}