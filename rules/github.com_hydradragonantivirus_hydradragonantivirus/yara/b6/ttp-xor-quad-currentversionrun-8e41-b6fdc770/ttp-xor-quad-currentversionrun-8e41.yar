rule TTP_XOR_QUAD_CurrentVersionRun_8e41 {
  strings:
    $key_8e41 = { dd 2e [2] f9 20 [2] d2 0c [2] fc 2e [2] e8 35 [2] e7 2f [2] f9 32 [2] fb 33 [2] e0 35 [2] fc 32 [2] e0 1d }

  condition:
    any of them
}