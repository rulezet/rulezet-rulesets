rule TTP_XOR_QUAD_CurrentVersionRun_8e61 {
  strings:
    $key_8e61 = { dd 0e [2] f9 00 [2] d2 2c [2] fc 0e [2] e8 15 [2] e7 0f [2] f9 12 [2] fb 13 [2] e0 15 [2] fc 12 [2] e0 3d }

  condition:
    any of them
}