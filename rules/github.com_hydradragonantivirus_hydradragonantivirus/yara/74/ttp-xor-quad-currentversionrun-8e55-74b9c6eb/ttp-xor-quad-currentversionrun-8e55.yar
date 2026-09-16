rule TTP_XOR_QUAD_CurrentVersionRun_8e55 {
  strings:
    $key_8e55 = { dd 3a [2] f9 34 [2] d2 18 [2] fc 3a [2] e8 21 [2] e7 3b [2] f9 26 [2] fb 27 [2] e0 21 [2] fc 26 [2] e0 09 }

  condition:
    any of them
}