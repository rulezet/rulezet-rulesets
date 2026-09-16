rule TTP_XOR_QUAD_CurrentVersionRun_8b10 {
  strings:
    $key_8b10 = { d8 7f [2] fc 71 [2] d7 5d [2] f9 7f [2] ed 64 [2] e2 7e [2] fc 63 [2] fe 62 [2] e5 64 [2] f9 63 [2] e5 4c }

  condition:
    any of them
}