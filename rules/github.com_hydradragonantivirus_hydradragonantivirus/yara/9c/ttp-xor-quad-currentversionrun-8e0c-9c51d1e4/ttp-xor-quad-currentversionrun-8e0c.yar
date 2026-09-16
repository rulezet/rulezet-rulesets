rule TTP_XOR_QUAD_CurrentVersionRun_8e0c {
  strings:
    $key_8e0c = { dd 63 [2] f9 6d [2] d2 41 [2] fc 63 [2] e8 78 [2] e7 62 [2] f9 7f [2] fb 7e [2] e0 78 [2] fc 7f [2] e0 50 }

  condition:
    any of them
}