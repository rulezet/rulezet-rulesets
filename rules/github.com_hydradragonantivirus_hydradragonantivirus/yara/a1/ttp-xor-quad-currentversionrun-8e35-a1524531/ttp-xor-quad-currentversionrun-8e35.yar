rule TTP_XOR_QUAD_CurrentVersionRun_8e35 {
  strings:
    $key_8e35 = { dd 5a [2] f9 54 [2] d2 78 [2] fc 5a [2] e8 41 [2] e7 5b [2] f9 46 [2] fb 47 [2] e0 41 [2] fc 46 [2] e0 69 }

  condition:
    any of them
}