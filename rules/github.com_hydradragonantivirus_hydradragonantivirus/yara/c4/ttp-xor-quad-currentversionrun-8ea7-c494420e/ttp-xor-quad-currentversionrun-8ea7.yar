rule TTP_XOR_QUAD_CurrentVersionRun_8ea7 {
  strings:
    $key_8ea7 = { dd c8 [2] f9 c6 [2] d2 ea [2] fc c8 [2] e8 d3 [2] e7 c9 [2] f9 d4 [2] fb d5 [2] e0 d3 [2] fc d4 [2] e0 fb }

  condition:
    any of them
}