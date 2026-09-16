rule TTP_XOR_QUAD_CurrentVersionRun_8e5b {
  strings:
    $key_8e5b = { dd 34 [2] f9 3a [2] d2 16 [2] fc 34 [2] e8 2f [2] e7 35 [2] f9 28 [2] fb 29 [2] e0 2f [2] fc 28 [2] e0 07 }

  condition:
    any of them
}