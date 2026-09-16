rule TTP_XOR_QUAD_CurrentVersionRun_8e10 {
  strings:
    $key_8e10 = { dd 7f [2] f9 71 [2] d2 5d [2] fc 7f [2] e8 64 [2] e7 7e [2] f9 63 [2] fb 62 [2] e0 64 [2] fc 63 [2] e0 4c }

  condition:
    any of them
}