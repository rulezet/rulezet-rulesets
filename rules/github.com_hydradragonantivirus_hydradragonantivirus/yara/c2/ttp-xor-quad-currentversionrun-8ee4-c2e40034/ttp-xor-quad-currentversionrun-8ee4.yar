rule TTP_XOR_QUAD_CurrentVersionRun_8ee4 {
  strings:
    $key_8ee4 = { dd 8b [2] f9 85 [2] d2 a9 [2] fc 8b [2] e8 90 [2] e7 8a [2] f9 97 [2] fb 96 [2] e0 90 [2] fc 97 [2] e0 b8 }

  condition:
    any of them
}