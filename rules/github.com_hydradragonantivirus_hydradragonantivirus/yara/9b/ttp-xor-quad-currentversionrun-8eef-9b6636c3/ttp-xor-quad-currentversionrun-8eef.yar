rule TTP_XOR_QUAD_CurrentVersionRun_8eef {
  strings:
    $key_8eef = { dd 80 [2] f9 8e [2] d2 a2 [2] fc 80 [2] e8 9b [2] e7 81 [2] f9 9c [2] fb 9d [2] e0 9b [2] fc 9c [2] e0 b3 }

  condition:
    any of them
}