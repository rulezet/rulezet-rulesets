rule TTP_XOR_QUAD_CurrentVersionRun_8e5f {
  strings:
    $key_8e5f = { dd 30 [2] f9 3e [2] d2 12 [2] fc 30 [2] e8 2b [2] e7 31 [2] f9 2c [2] fb 2d [2] e0 2b [2] fc 2c [2] e0 03 }

  condition:
    any of them
}