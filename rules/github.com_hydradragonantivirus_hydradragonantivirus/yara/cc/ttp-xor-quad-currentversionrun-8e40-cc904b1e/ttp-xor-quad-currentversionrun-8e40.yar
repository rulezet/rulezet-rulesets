rule TTP_XOR_QUAD_CurrentVersionRun_8e40 {
  strings:
    $key_8e40 = { dd 2f [2] f9 21 [2] d2 0d [2] fc 2f [2] e8 34 [2] e7 2e [2] f9 33 [2] fb 32 [2] e0 34 [2] fc 33 [2] e0 1c }

  condition:
    any of them
}