rule TTP_XOR_QUAD_CurrentVersionRun_8e06 {
  strings:
    $key_8e06 = { dd 69 [2] f9 67 [2] d2 4b [2] fc 69 [2] e8 72 [2] e7 68 [2] f9 75 [2] fb 74 [2] e0 72 [2] fc 75 [2] e0 5a }

  condition:
    any of them
}