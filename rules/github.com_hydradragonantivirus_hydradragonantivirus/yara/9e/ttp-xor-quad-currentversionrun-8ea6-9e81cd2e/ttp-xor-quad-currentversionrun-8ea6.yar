rule TTP_XOR_QUAD_CurrentVersionRun_8ea6 {
  strings:
    $key_8ea6 = { dd c9 [2] f9 c7 [2] d2 eb [2] fc c9 [2] e8 d2 [2] e7 c8 [2] f9 d5 [2] fb d4 [2] e0 d2 [2] fc d5 [2] e0 fa }

  condition:
    any of them
}