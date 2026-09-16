rule TTP_XOR_QUAD_CurrentVersionRun_8e4f {
  strings:
    $key_8e4f = { dd 20 [2] f9 2e [2] d2 02 [2] fc 20 [2] e8 3b [2] e7 21 [2] f9 3c [2] fb 3d [2] e0 3b [2] fc 3c [2] e0 13 }

  condition:
    any of them
}