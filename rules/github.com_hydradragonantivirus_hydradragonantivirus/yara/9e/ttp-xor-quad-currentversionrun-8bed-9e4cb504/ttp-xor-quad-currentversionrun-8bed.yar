rule TTP_XOR_QUAD_CurrentVersionRun_8bed {
  strings:
    $key_8bed = { d8 82 [2] fc 8c [2] d7 a0 [2] f9 82 [2] ed 99 [2] e2 83 [2] fc 9e [2] fe 9f [2] e5 99 [2] f9 9e [2] e5 b1 }

  condition:
    any of them
}