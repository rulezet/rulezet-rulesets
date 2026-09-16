rule TTP_XOR_QUAD_CurrentVersionRun_8e74 {
  strings:
    $key_8e74 = { dd 1b [2] f9 15 [2] d2 39 [2] fc 1b [2] e8 00 [2] e7 1a [2] f9 07 [2] fb 06 [2] e0 00 [2] fc 07 [2] e0 28 }

  condition:
    any of them
}