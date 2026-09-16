rule TTP_XOR_QUAD_CurrentVersionRun_8b21 {
  strings:
    $key_8b21 = { d8 4e [2] fc 40 [2] d7 6c [2] f9 4e [2] ed 55 [2] e2 4f [2] fc 52 [2] fe 53 [2] e5 55 [2] f9 52 [2] e5 7d }

  condition:
    any of them
}