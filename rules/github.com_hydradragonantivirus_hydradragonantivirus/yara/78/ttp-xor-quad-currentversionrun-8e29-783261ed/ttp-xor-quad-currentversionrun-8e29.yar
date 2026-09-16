rule TTP_XOR_QUAD_CurrentVersionRun_8e29 {
  strings:
    $key_8e29 = { dd 46 [2] f9 48 [2] d2 64 [2] fc 46 [2] e8 5d [2] e7 47 [2] f9 5a [2] fb 5b [2] e0 5d [2] fc 5a [2] e0 75 }

  condition:
    any of them
}