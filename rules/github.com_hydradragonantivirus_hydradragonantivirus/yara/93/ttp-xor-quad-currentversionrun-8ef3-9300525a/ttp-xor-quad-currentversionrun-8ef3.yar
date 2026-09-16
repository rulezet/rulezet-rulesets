rule TTP_XOR_QUAD_CurrentVersionRun_8ef3 {
  strings:
    $key_8ef3 = { dd 9c [2] f9 92 [2] d2 be [2] fc 9c [2] e8 87 [2] e7 9d [2] f9 80 [2] fb 81 [2] e0 87 [2] fc 80 [2] e0 af }

  condition:
    any of them
}