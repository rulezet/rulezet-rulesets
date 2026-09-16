rule TTP_XOR_QUAD_CurrentVersionRun_8e3b {
  strings:
    $key_8e3b = { dd 54 [2] f9 5a [2] d2 76 [2] fc 54 [2] e8 4f [2] e7 55 [2] f9 48 [2] fb 49 [2] e0 4f [2] fc 48 [2] e0 67 }

  condition:
    any of them
}