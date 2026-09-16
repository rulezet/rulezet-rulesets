rule TTP_XOR_QUAD_CurrentVersionRun_8ef1 {
  strings:
    $key_8ef1 = { dd 9e [2] f9 90 [2] d2 bc [2] fc 9e [2] e8 85 [2] e7 9f [2] f9 82 [2] fb 83 [2] e0 85 [2] fc 82 [2] e0 ad }

  condition:
    any of them
}