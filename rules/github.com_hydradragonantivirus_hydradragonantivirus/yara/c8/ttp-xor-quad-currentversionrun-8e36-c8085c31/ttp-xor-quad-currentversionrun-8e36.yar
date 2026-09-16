rule TTP_XOR_QUAD_CurrentVersionRun_8e36 {
  strings:
    $key_8e36 = { dd 59 [2] f9 57 [2] d2 7b [2] fc 59 [2] e8 42 [2] e7 58 [2] f9 45 [2] fb 44 [2] e0 42 [2] fc 45 [2] e0 6a }

  condition:
    any of them
}