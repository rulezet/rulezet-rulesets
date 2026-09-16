rule TTP_XOR_QUAD_CurrentVersionRun_8ee0 {
  strings:
    $key_8ee0 = { dd 8f [2] f9 81 [2] d2 ad [2] fc 8f [2] e8 94 [2] e7 8e [2] f9 93 [2] fb 92 [2] e0 94 [2] fc 93 [2] e0 bc }

  condition:
    any of them
}