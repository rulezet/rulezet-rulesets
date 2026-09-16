rule TTP_XOR_QUAD_CurrentVersionRun_8e6c {
  strings:
    $key_8e6c = { dd 03 [2] f9 0d [2] d2 21 [2] fc 03 [2] e8 18 [2] e7 02 [2] f9 1f [2] fb 1e [2] e0 18 [2] fc 1f [2] e0 30 }

  condition:
    any of them
}