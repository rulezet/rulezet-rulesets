rule TTP_XOR_QUAD_CurrentVersionRun_8e00 {
  strings:
    $key_8e00 = { dd 6f [2] f9 61 [2] d2 4d [2] fc 6f [2] e8 74 [2] e7 6e [2] f9 73 [2] fb 72 [2] e0 74 [2] fc 73 [2] e0 5c }

  condition:
    any of them
}