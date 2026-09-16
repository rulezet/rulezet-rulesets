rule TTP_XOR_QUAD_CurrentVersionRun_8e33 {
  strings:
    $key_8e33 = { dd 5c [2] f9 52 [2] d2 7e [2] fc 5c [2] e8 47 [2] e7 5d [2] f9 40 [2] fb 41 [2] e0 47 [2] fc 40 [2] e0 6f }

  condition:
    any of them
}