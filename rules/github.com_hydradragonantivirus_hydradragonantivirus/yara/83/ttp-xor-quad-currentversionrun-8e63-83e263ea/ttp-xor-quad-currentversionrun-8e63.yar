rule TTP_XOR_QUAD_CurrentVersionRun_8e63 {
  strings:
    $key_8e63 = { dd 0c [2] f9 02 [2] d2 2e [2] fc 0c [2] e8 17 [2] e7 0d [2] f9 10 [2] fb 11 [2] e0 17 [2] fc 10 [2] e0 3f }

  condition:
    any of them
}