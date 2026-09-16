rule TTP_XOR_QUAD_CurrentVersionRun_8e45 {
  strings:
    $key_8e45 = { dd 2a [2] f9 24 [2] d2 08 [2] fc 2a [2] e8 31 [2] e7 2b [2] f9 36 [2] fb 37 [2] e0 31 [2] fc 36 [2] e0 19 }

  condition:
    any of them
}