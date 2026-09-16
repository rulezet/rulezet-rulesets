rule TTP_XOR_QUAD_CurrentVersionRun_8b12 {
  strings:
    $key_8b12 = { d8 7d [2] fc 73 [2] d7 5f [2] f9 7d [2] ed 66 [2] e2 7c [2] fc 61 [2] fe 60 [2] e5 66 [2] f9 61 [2] e5 4e }

  condition:
    any of them
}