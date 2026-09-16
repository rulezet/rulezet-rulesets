rule TTP_XOR_QUAD_CurrentVersionRun_8e2b {
  strings:
    $key_8e2b = { dd 44 [2] f9 4a [2] d2 66 [2] fc 44 [2] e8 5f [2] e7 45 [2] f9 58 [2] fb 59 [2] e0 5f [2] fc 58 [2] e0 77 }

  condition:
    any of them
}