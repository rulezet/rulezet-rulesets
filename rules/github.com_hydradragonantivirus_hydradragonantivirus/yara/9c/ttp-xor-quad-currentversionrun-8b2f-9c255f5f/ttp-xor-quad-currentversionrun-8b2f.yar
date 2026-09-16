rule TTP_XOR_QUAD_CurrentVersionRun_8b2f {
  strings:
    $key_8b2f = { d8 40 [2] fc 4e [2] d7 62 [2] f9 40 [2] ed 5b [2] e2 41 [2] fc 5c [2] fe 5d [2] e5 5b [2] f9 5c [2] e5 73 }

  condition:
    any of them
}