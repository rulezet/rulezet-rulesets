rule TTP_XOR_QUAD_CurrentVersionRun_8e52 {
  strings:
    $key_8e52 = { dd 3d [2] f9 33 [2] d2 1f [2] fc 3d [2] e8 26 [2] e7 3c [2] f9 21 [2] fb 20 [2] e0 26 [2] fc 21 [2] e0 0e }

  condition:
    any of them
}