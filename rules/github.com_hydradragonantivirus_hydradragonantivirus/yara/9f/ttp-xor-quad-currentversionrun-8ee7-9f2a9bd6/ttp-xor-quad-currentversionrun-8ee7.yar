rule TTP_XOR_QUAD_CurrentVersionRun_8ee7 {
  strings:
    $key_8ee7 = { dd 88 [2] f9 86 [2] d2 aa [2] fc 88 [2] e8 93 [2] e7 89 [2] f9 94 [2] fb 95 [2] e0 93 [2] fc 94 [2] e0 bb }

  condition:
    any of them
}