rule TTP_XOR_QUAD_CurrentVersionRun_8bec {
  strings:
    $key_8bec = { d8 83 [2] fc 8d [2] d7 a1 [2] f9 83 [2] ed 98 [2] e2 82 [2] fc 9f [2] fe 9e [2] e5 98 [2] f9 9f [2] e5 b0 }

  condition:
    any of them
}