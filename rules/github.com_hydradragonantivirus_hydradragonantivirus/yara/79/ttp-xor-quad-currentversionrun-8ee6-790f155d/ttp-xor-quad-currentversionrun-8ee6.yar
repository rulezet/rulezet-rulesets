rule TTP_XOR_QUAD_CurrentVersionRun_8ee6 {
  strings:
    $key_8ee6 = { dd 89 [2] f9 87 [2] d2 ab [2] fc 89 [2] e8 92 [2] e7 88 [2] f9 95 [2] fb 94 [2] e0 92 [2] fc 95 [2] e0 ba }

  condition:
    any of them
}