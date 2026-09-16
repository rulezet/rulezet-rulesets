rule TTP_XOR_QUAD_CurrentVersionRun_8e25 {
  strings:
    $key_8e25 = { dd 4a [2] f9 44 [2] d2 68 [2] fc 4a [2] e8 51 [2] e7 4b [2] f9 56 [2] fb 57 [2] e0 51 [2] fc 56 [2] e0 79 }

  condition:
    any of them
}