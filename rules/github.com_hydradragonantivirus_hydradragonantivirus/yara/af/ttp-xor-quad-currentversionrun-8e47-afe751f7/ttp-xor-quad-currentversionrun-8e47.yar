rule TTP_XOR_QUAD_CurrentVersionRun_8e47 {
  strings:
    $key_8e47 = { dd 28 [2] f9 26 [2] d2 0a [2] fc 28 [2] e8 33 [2] e7 29 [2] f9 34 [2] fb 35 [2] e0 33 [2] fc 34 [2] e0 1b }

  condition:
    any of them
}