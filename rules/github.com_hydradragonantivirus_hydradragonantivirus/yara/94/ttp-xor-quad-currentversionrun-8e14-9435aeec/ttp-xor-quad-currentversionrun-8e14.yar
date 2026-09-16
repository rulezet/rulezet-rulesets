rule TTP_XOR_QUAD_CurrentVersionRun_8e14 {
  strings:
    $key_8e14 = { dd 7b [2] f9 75 [2] d2 59 [2] fc 7b [2] e8 60 [2] e7 7a [2] f9 67 [2] fb 66 [2] e0 60 [2] fc 67 [2] e0 48 }

  condition:
    any of them
}