rule TTP_XOR_QUAD_CurrentVersionRun_8e3c {
  strings:
    $key_8e3c = { dd 53 [2] f9 5d [2] d2 71 [2] fc 53 [2] e8 48 [2] e7 52 [2] f9 4f [2] fb 4e [2] e0 48 [2] fc 4f [2] e0 60 }

  condition:
    any of them
}