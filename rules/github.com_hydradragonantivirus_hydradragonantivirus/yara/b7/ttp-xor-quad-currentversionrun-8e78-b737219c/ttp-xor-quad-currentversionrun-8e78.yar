rule TTP_XOR_QUAD_CurrentVersionRun_8e78 {
  strings:
    $key_8e78 = { dd 17 [2] f9 19 [2] d2 35 [2] fc 17 [2] e8 0c [2] e7 16 [2] f9 0b [2] fb 0a [2] e0 0c [2] fc 0b [2] e0 24 }

  condition:
    any of them
}