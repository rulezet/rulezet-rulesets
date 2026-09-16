rule TTP_XOR_QUAD_CurrentVersionRun_8b41 {
  strings:
    $key_8b41 = { d8 2e [2] fc 20 [2] d7 0c [2] f9 2e [2] ed 35 [2] e2 2f [2] fc 32 [2] fe 33 [2] e5 35 [2] f9 32 [2] e5 1d }

  condition:
    any of them
}