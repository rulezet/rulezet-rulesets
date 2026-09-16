rule TTP_XOR_QUAD_CurrentVersionRun_8ee1 {
  strings:
    $key_8ee1 = { dd 8e [2] f9 80 [2] d2 ac [2] fc 8e [2] e8 95 [2] e7 8f [2] f9 92 [2] fb 93 [2] e0 95 [2] fc 92 [2] e0 bd }

  condition:
    any of them
}