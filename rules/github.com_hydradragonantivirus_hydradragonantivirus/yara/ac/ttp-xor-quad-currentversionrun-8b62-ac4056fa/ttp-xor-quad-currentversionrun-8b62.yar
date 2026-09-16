rule TTP_XOR_QUAD_CurrentVersionRun_8b62 {
  strings:
    $key_8b62 = { d8 0d [2] fc 03 [2] d7 2f [2] f9 0d [2] ed 16 [2] e2 0c [2] fc 11 [2] fe 10 [2] e5 16 [2] f9 11 [2] e5 3e }

  condition:
    any of them
}