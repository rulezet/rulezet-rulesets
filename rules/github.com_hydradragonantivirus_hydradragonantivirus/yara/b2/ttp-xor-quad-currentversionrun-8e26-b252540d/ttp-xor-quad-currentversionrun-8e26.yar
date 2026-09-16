rule TTP_XOR_QUAD_CurrentVersionRun_8e26 {
  strings:
    $key_8e26 = { dd 49 [2] f9 47 [2] d2 6b [2] fc 49 [2] e8 52 [2] e7 48 [2] f9 55 [2] fb 54 [2] e0 52 [2] fc 55 [2] e0 7a }

  condition:
    any of them
}