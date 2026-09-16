rule TTP_XOR_QUAD_CurrentVersionRun_8e0a {
  strings:
    $key_8e0a = { dd 65 [2] f9 6b [2] d2 47 [2] fc 65 [2] e8 7e [2] e7 64 [2] f9 79 [2] fb 78 [2] e0 7e [2] fc 79 [2] e0 56 }

  condition:
    any of them
}