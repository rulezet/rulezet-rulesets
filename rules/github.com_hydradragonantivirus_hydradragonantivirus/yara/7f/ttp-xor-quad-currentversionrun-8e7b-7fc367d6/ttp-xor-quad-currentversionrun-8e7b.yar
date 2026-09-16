rule TTP_XOR_QUAD_CurrentVersionRun_8e7b {
  strings:
    $key_8e7b = { dd 14 [2] f9 1a [2] d2 36 [2] fc 14 [2] e8 0f [2] e7 15 [2] f9 08 [2] fb 09 [2] e0 0f [2] fc 08 [2] e0 27 }

  condition:
    any of them
}