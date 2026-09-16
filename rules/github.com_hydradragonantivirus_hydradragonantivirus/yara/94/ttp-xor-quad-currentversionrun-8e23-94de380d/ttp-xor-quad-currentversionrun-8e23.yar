rule TTP_XOR_QUAD_CurrentVersionRun_8e23 {
  strings:
    $key_8e23 = { dd 4c [2] f9 42 [2] d2 6e [2] fc 4c [2] e8 57 [2] e7 4d [2] f9 50 [2] fb 51 [2] e0 57 [2] fc 50 [2] e0 7f }

  condition:
    any of them
}