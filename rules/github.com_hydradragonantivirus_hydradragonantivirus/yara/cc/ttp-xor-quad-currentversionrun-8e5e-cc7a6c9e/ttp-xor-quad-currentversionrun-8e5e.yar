rule TTP_XOR_QUAD_CurrentVersionRun_8e5e {
  strings:
    $key_8e5e = { dd 31 [2] f9 3f [2] d2 13 [2] fc 31 [2] e8 2a [2] e7 30 [2] f9 2d [2] fb 2c [2] e0 2a [2] fc 2d [2] e0 02 }

  condition:
    any of them
}