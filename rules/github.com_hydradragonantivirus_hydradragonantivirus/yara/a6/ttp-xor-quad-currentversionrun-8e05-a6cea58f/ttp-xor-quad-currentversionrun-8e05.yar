rule TTP_XOR_QUAD_CurrentVersionRun_8e05 {
  strings:
    $key_8e05 = { dd 6a [2] f9 64 [2] d2 48 [2] fc 6a [2] e8 71 [2] e7 6b [2] f9 76 [2] fb 77 [2] e0 71 [2] fc 76 [2] e0 59 }

  condition:
    any of them
}