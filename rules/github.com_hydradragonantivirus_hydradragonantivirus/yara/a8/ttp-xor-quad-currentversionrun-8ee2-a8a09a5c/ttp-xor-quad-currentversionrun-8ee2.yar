rule TTP_XOR_QUAD_CurrentVersionRun_8ee2 {
  strings:
    $key_8ee2 = { dd 8d [2] f9 83 [2] d2 af [2] fc 8d [2] e8 96 [2] e7 8c [2] f9 91 [2] fb 90 [2] e0 96 [2] fc 91 [2] e0 be }

  condition:
    any of them
}