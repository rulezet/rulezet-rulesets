rule TTP_XOR_QUAD_CurrentVersionRun_8e4b {
  strings:
    $key_8e4b = { dd 24 [2] f9 2a [2] d2 06 [2] fc 24 [2] e8 3f [2] e7 25 [2] f9 38 [2] fb 39 [2] e0 3f [2] fc 38 [2] e0 17 }

  condition:
    any of them
}