rule TTP_XOR_QUAD_CurrentVersionRun_8e77 {
  strings:
    $key_8e77 = { dd 18 [2] f9 16 [2] d2 3a [2] fc 18 [2] e8 03 [2] e7 19 [2] f9 04 [2] fb 05 [2] e0 03 [2] fc 04 [2] e0 2b }

  condition:
    any of them
}