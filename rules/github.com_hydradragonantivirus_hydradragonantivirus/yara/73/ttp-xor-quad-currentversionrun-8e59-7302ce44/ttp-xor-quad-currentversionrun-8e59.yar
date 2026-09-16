rule TTP_XOR_QUAD_CurrentVersionRun_8e59 {
  strings:
    $key_8e59 = { dd 36 [2] f9 38 [2] d2 14 [2] fc 36 [2] e8 2d [2] e7 37 [2] f9 2a [2] fb 2b [2] e0 2d [2] fc 2a [2] e0 05 }

  condition:
    any of them
}