rule TTP_XOR_QUAD_CurrentVersionRun_8b3d {
  strings:
    $key_8b3d = { d8 52 [2] fc 5c [2] d7 70 [2] f9 52 [2] ed 49 [2] e2 53 [2] fc 4e [2] fe 4f [2] e5 49 [2] f9 4e [2] e5 61 }

  condition:
    any of them
}