rule TTP_XOR_QUAD_CurrentVersionRun_8e49 {
  strings:
    $key_8e49 = { dd 26 [2] f9 28 [2] d2 04 [2] fc 26 [2] e8 3d [2] e7 27 [2] f9 3a [2] fb 3b [2] e0 3d [2] fc 3a [2] e0 15 }

  condition:
    any of them
}