rule TTP_XOR_QUAD_CurrentVersionRun_8e64 {
  strings:
    $key_8e64 = { dd 0b [2] f9 05 [2] d2 29 [2] fc 0b [2] e8 10 [2] e7 0a [2] f9 17 [2] fb 16 [2] e0 10 [2] fc 17 [2] e0 38 }

  condition:
    any of them
}