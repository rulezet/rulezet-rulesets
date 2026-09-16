rule TTP_XOR_QUAD_CurrentVersionRun_8e15 {
  strings:
    $key_8e15 = { dd 7a [2] f9 74 [2] d2 58 [2] fc 7a [2] e8 61 [2] e7 7b [2] f9 66 [2] fb 67 [2] e0 61 [2] fc 66 [2] e0 49 }

  condition:
    any of them
}