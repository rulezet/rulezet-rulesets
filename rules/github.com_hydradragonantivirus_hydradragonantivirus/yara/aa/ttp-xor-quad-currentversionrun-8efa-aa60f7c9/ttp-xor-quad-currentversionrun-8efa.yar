rule TTP_XOR_QUAD_CurrentVersionRun_8efa {
  strings:
    $key_8efa = { dd 95 [2] f9 9b [2] d2 b7 [2] fc 95 [2] e8 8e [2] e7 94 [2] f9 89 [2] fb 88 [2] e0 8e [2] fc 89 [2] e0 a6 }

  condition:
    any of them
}