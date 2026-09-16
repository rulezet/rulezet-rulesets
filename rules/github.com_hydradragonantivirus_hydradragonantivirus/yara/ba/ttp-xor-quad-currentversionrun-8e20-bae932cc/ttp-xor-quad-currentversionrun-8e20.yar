rule TTP_XOR_QUAD_CurrentVersionRun_8e20 {
  strings:
    $key_8e20 = { dd 4f [2] f9 41 [2] d2 6d [2] fc 4f [2] e8 54 [2] e7 4e [2] f9 53 [2] fb 52 [2] e0 54 [2] fc 53 [2] e0 7c }

  condition:
    any of them
}