rule TTP_XOR_QUAD_CurrentVersionRun_8b22 {
  strings:
    $key_8b22 = { d8 4d [2] fc 43 [2] d7 6f [2] f9 4d [2] ed 56 [2] e2 4c [2] fc 51 [2] fe 50 [2] e5 56 [2] f9 51 [2] e5 7e }

  condition:
    any of them
}