rule TTP_XOR_QUAD_CurrentVersionRun_8e56 {
  strings:
    $key_8e56 = { dd 39 [2] f9 37 [2] d2 1b [2] fc 39 [2] e8 22 [2] e7 38 [2] f9 25 [2] fb 24 [2] e0 22 [2] fc 25 [2] e0 0a }

  condition:
    any of them
}