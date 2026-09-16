rule TTP_XOR_QUAD_CurrentVersionRun_8e4e {
  strings:
    $key_8e4e = { dd 21 [2] f9 2f [2] d2 03 [2] fc 21 [2] e8 3a [2] e7 20 [2] f9 3d [2] fb 3c [2] e0 3a [2] fc 3d [2] e0 12 }

  condition:
    any of them
}