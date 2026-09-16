rule TTP_XOR_QUAD_CurrentVersionRun_8b71 {
  strings:
    $key_8b71 = { d8 1e [2] fc 10 [2] d7 3c [2] f9 1e [2] ed 05 [2] e2 1f [2] fc 02 [2] fe 03 [2] e5 05 [2] f9 02 [2] e5 2d }

  condition:
    any of them
}