rule TTP_XOR_QUAD_CurrentVersionRun_8efc {
  strings:
    $key_8efc = { dd 93 [2] f9 9d [2] d2 b1 [2] fc 93 [2] e8 88 [2] e7 92 [2] f9 8f [2] fb 8e [2] e0 88 [2] fc 8f [2] e0 a0 }

  condition:
    any of them
}