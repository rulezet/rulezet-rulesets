rule TTP_XOR_QUAD_CurrentVersionRun_8b31 {
  strings:
    $key_8b31 = { d8 5e [2] fc 50 [2] d7 7c [2] f9 5e [2] ed 45 [2] e2 5f [2] fc 42 [2] fe 43 [2] e5 45 [2] f9 42 [2] e5 6d }

  condition:
    any of them
}