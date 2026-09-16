rule TTP_XOR_QUAD_CurrentVersionRun_8e07 {
  strings:
    $key_8e07 = { dd 68 [2] f9 66 [2] d2 4a [2] fc 68 [2] e8 73 [2] e7 69 [2] f9 74 [2] fb 75 [2] e0 73 [2] fc 74 [2] e0 5b }

  condition:
    any of them
}