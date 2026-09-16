rule TTP_XOR_QUAD_CurrentVersionRun_8e67 {
  strings:
    $key_8e67 = { dd 08 [2] f9 06 [2] d2 2a [2] fc 08 [2] e8 13 [2] e7 09 [2] f9 14 [2] fb 15 [2] e0 13 [2] fc 14 [2] e0 3b }

  condition:
    any of them
}