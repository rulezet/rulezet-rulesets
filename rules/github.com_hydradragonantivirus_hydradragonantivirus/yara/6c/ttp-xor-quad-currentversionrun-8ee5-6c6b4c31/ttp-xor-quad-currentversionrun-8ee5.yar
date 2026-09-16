rule TTP_XOR_QUAD_CurrentVersionRun_8ee5 {
  strings:
    $key_8ee5 = { dd 8a [2] f9 84 [2] d2 a8 [2] fc 8a [2] e8 91 [2] e7 8b [2] f9 96 [2] fb 97 [2] e0 91 [2] fc 96 [2] e0 b9 }

  condition:
    any of them
}