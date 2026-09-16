rule TTP_XOR_QUAD_CurrentVersionRun_8e7f {
  strings:
    $key_8e7f = { dd 10 [2] f9 1e [2] d2 32 [2] fc 10 [2] e8 0b [2] e7 11 [2] f9 0c [2] fb 0d [2] e0 0b [2] fc 0c [2] e0 23 }

  condition:
    any of them
}