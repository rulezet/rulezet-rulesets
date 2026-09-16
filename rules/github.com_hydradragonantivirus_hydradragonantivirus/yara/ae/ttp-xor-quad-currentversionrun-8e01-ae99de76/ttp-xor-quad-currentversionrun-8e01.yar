rule TTP_XOR_QUAD_CurrentVersionRun_8e01 {
  strings:
    $key_8e01 = { dd 6e [2] f9 60 [2] d2 4c [2] fc 6e [2] e8 75 [2] e7 6f [2] f9 72 [2] fb 73 [2] e0 75 [2] fc 72 [2] e0 5d }

  condition:
    any of them
}