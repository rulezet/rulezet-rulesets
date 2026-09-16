rule TTP_XOR_QUAD_CurrentVersionRun_8e3d {
  strings:
    $key_8e3d = { dd 52 [2] f9 5c [2] d2 70 [2] fc 52 [2] e8 49 [2] e7 53 [2] f9 4e [2] fb 4f [2] e0 49 [2] fc 4e [2] e0 61 }

  condition:
    any of them
}