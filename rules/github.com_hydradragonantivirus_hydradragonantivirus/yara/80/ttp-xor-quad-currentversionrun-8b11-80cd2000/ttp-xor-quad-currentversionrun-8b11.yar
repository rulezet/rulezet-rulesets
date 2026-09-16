rule TTP_XOR_QUAD_CurrentVersionRun_8b11 {
  strings:
    $key_8b11 = { d8 7e [2] fc 70 [2] d7 5c [2] f9 7e [2] ed 65 [2] e2 7f [2] fc 62 [2] fe 63 [2] e5 65 [2] f9 62 [2] e5 4d }

  condition:
    any of them
}