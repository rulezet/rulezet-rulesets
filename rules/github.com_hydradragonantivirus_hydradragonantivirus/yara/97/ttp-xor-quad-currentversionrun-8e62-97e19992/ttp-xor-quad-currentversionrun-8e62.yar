rule TTP_XOR_QUAD_CurrentVersionRun_8e62 {
  strings:
    $key_8e62 = { dd 0d [2] f9 03 [2] d2 2f [2] fc 0d [2] e8 16 [2] e7 0c [2] f9 11 [2] fb 10 [2] e0 16 [2] fc 11 [2] e0 3e }

  condition:
    any of them
}