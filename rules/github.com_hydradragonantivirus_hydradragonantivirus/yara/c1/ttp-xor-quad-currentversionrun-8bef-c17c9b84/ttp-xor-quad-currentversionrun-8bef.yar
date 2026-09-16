rule TTP_XOR_QUAD_CurrentVersionRun_8bef {
  strings:
    $key_8bef = { d8 80 [2] fc 8e [2] d7 a2 [2] f9 80 [2] ed 9b [2] e2 81 [2] fc 9c [2] fe 9d [2] e5 9b [2] f9 9c [2] e5 b3 }

  condition:
    any of them
}