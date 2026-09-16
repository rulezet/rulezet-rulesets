rule TTP_XOR_QUAD_CurrentVersionRun_8e68 {
  strings:
    $key_8e68 = { dd 07 [2] f9 09 [2] d2 25 [2] fc 07 [2] e8 1c [2] e7 06 [2] f9 1b [2] fb 1a [2] e0 1c [2] fc 1b [2] e0 34 }

  condition:
    any of them
}