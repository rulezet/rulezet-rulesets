rule TTP_XOR_QUAD_CurrentVersionRun_8e44 {
  strings:
    $key_8e44 = { dd 2b [2] f9 25 [2] d2 09 [2] fc 2b [2] e8 30 [2] e7 2a [2] f9 37 [2] fb 36 [2] e0 30 [2] fc 37 [2] e0 18 }

  condition:
    any of them
}