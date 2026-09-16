rule TTP_XOR_QUAD_CurrentVersionRun_8e4d {
  strings:
    $key_8e4d = { dd 22 [2] f9 2c [2] d2 00 [2] fc 22 [2] e8 39 [2] e7 23 [2] f9 3e [2] fb 3f [2] e0 39 [2] fc 3e [2] e0 11 }

  condition:
    any of them
}