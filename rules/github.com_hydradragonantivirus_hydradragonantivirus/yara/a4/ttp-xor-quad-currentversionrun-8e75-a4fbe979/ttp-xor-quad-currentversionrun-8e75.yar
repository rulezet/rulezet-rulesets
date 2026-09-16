rule TTP_XOR_QUAD_CurrentVersionRun_8e75 {
  strings:
    $key_8e75 = { dd 1a [2] f9 14 [2] d2 38 [2] fc 1a [2] e8 01 [2] e7 1b [2] f9 06 [2] fb 07 [2] e0 01 [2] fc 06 [2] e0 29 }

  condition:
    any of them
}