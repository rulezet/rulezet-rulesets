rule TTP_XOR_QUAD_CurrentVersionRun_8eea {
  strings:
    $key_8eea = { dd 85 [2] f9 8b [2] d2 a7 [2] fc 85 [2] e8 9e [2] e7 84 [2] f9 99 [2] fb 98 [2] e0 9e [2] fc 99 [2] e0 b6 }

  condition:
    any of them
}