rule TTP_XOR_QUAD_CurrentVersionRun_8bff {
  strings:
    $key_8bff = { d8 90 [2] fc 9e [2] d7 b2 [2] f9 90 [2] ed 8b [2] e2 91 [2] fc 8c [2] fe 8d [2] e5 8b [2] f9 8c [2] e5 a3 }

  condition:
    any of them
}