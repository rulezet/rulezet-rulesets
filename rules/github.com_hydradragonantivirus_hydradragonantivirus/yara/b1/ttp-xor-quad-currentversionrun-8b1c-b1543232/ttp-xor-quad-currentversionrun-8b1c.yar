rule TTP_XOR_QUAD_CurrentVersionRun_8b1c {
  strings:
    $key_8b1c = { d8 73 [2] fc 7d [2] d7 51 [2] f9 73 [2] ed 68 [2] e2 72 [2] fc 6f [2] fe 6e [2] e5 68 [2] f9 6f [2] e5 40 }

  condition:
    any of them
}