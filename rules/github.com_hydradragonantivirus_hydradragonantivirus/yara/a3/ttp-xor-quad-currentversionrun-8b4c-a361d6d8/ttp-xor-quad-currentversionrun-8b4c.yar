rule TTP_XOR_QUAD_CurrentVersionRun_8b4c {
  strings:
    $key_8b4c = { d8 23 [2] fc 2d [2] d7 01 [2] f9 23 [2] ed 38 [2] e2 22 [2] fc 3f [2] fe 3e [2] e5 38 [2] f9 3f [2] e5 10 }

  condition:
    any of them
}