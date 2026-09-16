rule TTP_XOR_QUAD_CurrentVersionRun_8e37 {
  strings:
    $key_8e37 = { dd 58 [2] f9 56 [2] d2 7a [2] fc 58 [2] e8 43 [2] e7 59 [2] f9 44 [2] fb 45 [2] e0 43 [2] fc 44 [2] e0 6b }

  condition:
    any of them
}