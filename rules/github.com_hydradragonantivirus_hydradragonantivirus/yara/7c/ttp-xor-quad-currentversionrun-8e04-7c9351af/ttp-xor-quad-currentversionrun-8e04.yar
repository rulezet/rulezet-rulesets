rule TTP_XOR_QUAD_CurrentVersionRun_8e04 {
  strings:
    $key_8e04 = { dd 6b [2] f9 65 [2] d2 49 [2] fc 6b [2] e8 70 [2] e7 6a [2] f9 77 [2] fb 76 [2] e0 70 [2] fc 77 [2] e0 58 }

  condition:
    any of them
}